// Copyright (c) 2024-2026 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mixclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/mixing"
	"github.com/decred/dcrd/mixing/internal/chacha20prng"
	"github.com/decred/dcrd/mixing/mixpool"
	"github.com/decred/dcrd/wire"
)

var errBlameFailed = errors.New("blame failed")

// blamedIdentities identifies detected misbehaving peers.
//
// If a run returns a blamedIdentities error, these peers are immediately
// excluded and the next run is started.  This can only be done in situations
// where all peers observe the misbehavior as the run is performed.
//
// If a run errors but blame requires revealing secrets and blame assignment,
// a blamedIdentities error will be returned by the blame function.
type blamedIdentities []identity

func (e blamedIdentities) Error() string {
	return "blamed peers " + e.String()
}

func (e blamedIdentities) String() string {
	buf := new(bytes.Buffer)
	buf.WriteByte('[')
	for i, id := range e {
		if i != 0 {
			buf.WriteByte(' ')
		}
		fmt.Fprintf(buf, "%x", id[:])
	}
	buf.WriteByte(']')
	return buf.String()
}

// confirmedLocalCoinjoin returns the coinjoin of an active local peer that
// produced a valid confirmation, along with true, if every active local peer
// confirmed.  When every local peer confirmed, a fully-signed CoinJoin
// transaction for the run may exist and revealing secrets could be unsafe.
// The returned coinjoin holds the mixed outputs that were confirmed.
func confirmedLocalCoinjoin(sesRun *sessionRun) (*CoinJoin, bool) {
	var cj *CoinJoin
	for _, p := range sesRun.localPeers {
		if p.isRemoteOrCanceled() {
			continue
		}
		if p.cm == nil {
			return nil, false
		}
		if cj == nil {
			cj = p.coinjoin
		}
	}
	return cj, cj != nil
}

// revealsExplainedByValidMix reports whether every revealer's disclosed mixed
// outputs are already present in the confirmed coinjoin.  When true, each
// revealer could have confirmed the run instead of revealing (its outputs are
// in a valid mix), so the reveal was gratuitous and a publishable transaction
// may exist.  When false, at least one revealer's output is missing from the
// mix, meaning it genuinely could not confirm and no valid transaction exists,
// so revealing secrets to assign blame is safe.
func revealsExplainedByValidMix(cj *CoinJoin, revealers []*wire.MsgMixSecrets) bool {
	mixed := make(map[[20]byte]struct{})
	for _, out := range cj.tx.TxOut {
		if out.Value != cj.mixValue || out.Version != 0 {
			continue
		}
		if len(out.PkScript) != 25 {
			continue
		}
		var h [20]byte
		copy(h[:], out.PkScript[3:23])
		mixed[h] = struct{}{}
	}
	for _, rs := range revealers {
		if len(rs.DCNetMsgs) == 0 {
			return false
		}
		for _, m := range rs.DCNetMsgs {
			if _, ok := mixed[m]; !ok {
				return false
			}
		}
	}
	return true
}

func (c *Client) blame(ctx context.Context, sesRun *sessionRun) (err error) {
	sesRun.logf("running blame assignment")

	mp := c.mixpool
	prs := sesRun.prs

	identityIndices := make(map[identity]int)
	for i, pr := range prs {
		identityIndices[pr.Identity] = i
	}

	var blamed blamedIdentities
	defer func() {
		if len(blamed) > 0 {
			c.log(blamed)
		}
	}()

	// Preserve the DiceMix-Light invariant that secrets are only revealed
	// for a run whose CoinJoin transaction cannot be published.  A peer's
	// revealed secrets expose the mixed outputs (HASH160s) it contributed
	// to the DC-net, tagged with its identity; revealing them for a run
	// whose transaction can still be broadcast deanonymizes the peer.
	//
	// When every local peer produced a valid confirmation, a fully-signed
	// transaction may already exist: a remote peer can withhold only its own
	// confirmation while collecting everyone else's from the mixpool, and
	// then broadcast the CoinJoin itself.  In that case, examine the secrets
	// that induced this blame round.  A revealer whose disclosed outputs are
	// all present in the confirmed mix could have confirmed instead of
	// revealing, so its reveal is gratuitous and a publishable transaction
	// exists -- refuse to reveal and blame the revealers by identity.  If
	// instead some revealer's output is missing from the mix, it genuinely
	// could not confirm (its slot was disrupted); no valid transaction exists
	// and the normal reveal-and-blame path below runs to identify the
	// disruptor.
	if cj, ok := confirmedLocalCoinjoin(sesRun); ok {
		// The secrets that induced this blame round are already in the
		// mixpool, so collect what is currently present with a short
		// timeout rather than blocking for the full blame window; a
		// longer wait would delay peers that fall through to the normal
		// reveal path and desynchronize them from the other peers.
		rcv := new(mixpool.Received)
		rcv.Sid = sesRun.sid
		rcv.RSs = make([]*wire.MsgMixSecrets, 0, len(prs))
		rcvCtx, rcvCtxCancel := context.WithTimeout(ctx, 2*time.Second)
		_ = mp.Receive(rcvCtx, rcv)
		rcvCtxCancel()

		var revealers []*wire.MsgMixSecrets
		for _, rs := range rcv.RSs {
			if _, ok := sesRun.localPeers[rs.Identity]; ok {
				continue
			}
			revealers = append(revealers, rs)
		}

		switch {
		case len(revealers) == 0:
			// Blame was induced by secrets that are no longer
			// retrievable.  With every local peer confirmed a
			// publishable transaction may exist, so do not reveal;
			// abort rather than risk deanonymizing local peers.
			return errBlameFailed

		case revealsExplainedByValidMix(cj, revealers):
			// Every revealer could have confirmed the run (its
			// outputs are in the confirmed mix), so the reveal is
			// gratuitous and a publishable transaction exists.  Do
			// not reveal; blame the revealers by identity.
			for _, rs := range revealers {
				sesRun.logf("blaming %x for revealing secrets on a publishable run",
					rs.Identity[:])
				blamed = append(blamed, rs.Identity)
			}
			return blamed
		}

		// Otherwise a revealer's output is missing from the mix: it
		// genuinely could not confirm, no valid transaction exists, and
		// revealing to assign blame is safe.  Fall through.
	}

	deadline := time.Now().Add(timeoutDuration)

	// Send initial secrets messages from any peers who detected
	// misbehavior.
	err = c.sendLocalPeerMsgs(ctx, deadline, sesRun, 0)
	if err != nil {
		return err
	}

	// Receive currently-revealed secrets
	rcv := new(mixpool.Received)
	rcv.Sid = sesRun.sid
	rcv.RSs = make([]*wire.MsgMixSecrets, 0, 1)
	_ = mp.Receive(ctx, rcv)
	rsHashes := make([]chainhash.Hash, 0, len(rcv.RSs))
	for _, rs := range rcv.RSs {
		rsHashes = append(rsHashes, rs.Hash())
	}

	// Send remaining secrets messages with observed RS hashes from the
	// initial peers who published secrets.
	c.forLocalPeers(ctx, sesRun, func(p *peer) error {
		if !p.triggeredBlame {
			if p.rs != nil {
				p.rs.SeenSecrets = rsHashes
			}
		}
		return nil
	})
	err = c.sendLocalPeerMsgs(ctx, deadline, sesRun, msgRS)
	if err != nil {
		return err
	}

	// Wait for all secrets, or timeout.
	rcv.RSs = make([]*wire.MsgMixSecrets, 0, len(sesRun.prs))
	rcvCtx, rcvCtxCancel := context.WithTimeout(ctx, timeoutDuration)
	_ = mp.Receive(rcvCtx, rcv)
	rcvCtxCancel()
	rss := rcv.RSs
	for _, rs := range rcv.RSs {
		if idx, ok := identityIndices[rs.Identity]; ok {
			sesRun.peers[idx].rs = rs
		}
	}
	if len(rss) != len(sesRun.peers) {
		// Blame peers who did not send secrets
		sesRun.logf("received %d RSs for %d peers; blaming unresponsive peers",
			len(rss), len(sesRun.peers))

		for _, p := range sesRun.peers {
			if p.rs != nil {
				continue
			}
			sesRun.logf("blaming %x for RS timeout", p.id[:])
			blamed = append(blamed, *p.id)
		}
		return blamed
	}
	sort.Slice(rss, func(i, j int) bool {
		a := identityIndices[rss[i].Identity]
		b := identityIndices[rss[j].Identity]
		return a < b
	})

	// If blame cannot be assigned on a failed mix, blame the peers who
	// reported failure.
	defer func() {
		if err != nil {
			return
		}
		for _, rs := range rss {
			if len(rs.PrevMsgs()) != 0 {
				continue
			}
			id := &rs.Identity
			sesRun.logf("blaming %x for false failure accusation", id[:])
			blamed = append(blamed, *id)
		}
		if len(blamed) > 0 {
			err = blamed
		} else {
			err = errBlameFailed
		}
	}()

	defer c.mu.Unlock()
	c.mu.Lock()

	var start uint32
	starts := make([]uint32, 0, len(prs))
	ecdh := make([]*secp256k1.PublicKey, 0, len(prs))
	pqpk := make([]*mixing.PQPublicKey, 0, len(prs))
	scratch := new(big.Int)
KELoop:
	for _, p := range sesRun.peers {
		if p.ke == nil {
			sesRun.logf("blaming %x for missing messages", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// Blame when revealed secrets do not match prior commitment to the secrets.
		c.blake256HasherMu.Lock()
		cm := p.rs.Commitment(c.blake256Hasher)
		c.blake256HasherMu.Unlock()
		if cm != p.ke.Commitment {
			sesRun.logf("blaming %x for false commitment, got %x want %x",
				p.id[:], cm[:], p.ke.Commitment[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// Blame peers whose seed is not the correct length (will panic chacha20prng).
		if len(p.rs.Seed) != chacha20prng.SeedSize {
			sesRun.logf("blaming %x for bad seed size in RS message", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// Blame peers with SR messages outside of the field.
		for _, m := range p.rs.SlotReserveMsgs {
			if mixing.InField(scratch.SetBytes(m)) {
				continue
			}
			sesRun.logf("blaming %x for SR message outside field", p.id[:])
			blamed = append(blamed, *p.id)
			continue KELoop
		}

		// Recover or initialize PRNG from seed and the last run that
		// caused secrets to be generated.
		p.prng = chacha20prng.New(p.rs.Seed[:], 0)

		// Recover derived key exchange from PRNG.
		p.kx, err = mixing.NewKX(p.prng)
		if err != nil {
			sesRun.logf("blaming %x for bad KX", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// Blame when published ECDH or PQ public keys differ from
		// those recovered from the PRNG.
		switch {
		case !bytes.Equal(p.ke.ECDH[:], p.kx.ECDHPublicKey.SerializeCompressed()):
			fallthrough
		case !bytes.Equal(p.ke.PQPK[:], p.kx.PQPublicKey[:]):
			sesRun.logf("blaming %x for KE public keys not derived from their PRNG",
				p.id[:])
			blamed = append(blamed, *p.id)
			continue KELoop
		}
		publishedECDHPub, err := secp256k1.ParsePubKey(p.ke.ECDH[:])
		if err != nil {
			sesRun.logf("blaming %x for unparsable pubkey")
			blamed = append(blamed, *p.id)
			continue
		}
		ecdh = append(ecdh, publishedECDHPub)
		pqpk = append(pqpk, &p.ke.PQPK)

		mcount := p.pr.MessageCount
		starts = append(starts, start)
		start += mcount

		if uint32(len(p.rs.SlotReserveMsgs)) != mcount || uint32(len(p.rs.DCNetMsgs)) != mcount {
			sesRun.logf("blaming %x for bad message count", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}
		srMsgInts := make([]*big.Int, len(p.rs.SlotReserveMsgs))
		for i, m := range p.rs.SlotReserveMsgs {
			srMsgInts[i] = new(big.Int).SetBytes(m)
		}
		p.srMsg = srMsgInts
		p.dcMsg = p.rs.DCNetMsgs
	}
	if len(blamed) > 0 {
		return blamed
	}

	// Recreate shared keys and ciphertexts from each peer's PRNG.
	recoveredCTs := make([][]mixing.PQCiphertext, 0, len(sesRun.peers))
	for _, p := range sesRun.peers {
		pqct, err := p.kx.Encapsulate(p.prng, pqpk, int(p.myVk))
		if err != nil {
			blamed = append(blamed, *p.id)
			continue
		}
		recoveredCTs = append(recoveredCTs, pqct)
	}
	if len(blamed) > 0 {
		return blamed
	}
	// Blame peers whose published ciphertexts differ from those recovered
	// from their PRNG.
	for i, p := range sesRun.peers {
		if p.ct == nil {
			sesRun.logf("blaming %x for missing messages", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}
		if len(recoveredCTs[i]) != len(p.ct.Ciphertexts) {
			sesRun.logf("blaming %x for different ciphertexts count %d != %d",
				p.id[:], len(recoveredCTs[i]), len(p.ct.Ciphertexts))
			blamed = append(blamed, *p.id)
			continue
		}
		for j := range p.ct.Ciphertexts {
			if !bytes.Equal(p.ct.Ciphertexts[j][:], recoveredCTs[i][j][:]) {
				sesRun.logf("blaming %x for different ciphertexts", p.id[:])
				blamed = append(blamed, *p.id)
				break
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	// Blame peers who share SR messages.
	shared := make(map[string][]identity)
	for _, p := range sesRun.peers {
		for _, m := range p.srMsg {
			key := string(m.Bytes())
			shared[key] = append(shared[key], *p.id)
		}
	}
	for _, pids := range shared {
		if len(pids) > 1 {
			for i := range pids {
				sesRun.logf("blaming %x for shared SR message", pids[i][:])
			}
			blamed = append(blamed, pids...)
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

SRLoop:
	for i, p := range sesRun.peers {
		if p.sr == nil {
			sesRun.logf("blaming %x for missing messages", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// Recover shared secrets
		revealed := &mixing.RevealedKeys{
			ECDHPublicKeys: ecdh,
			Ciphertexts:    make([]mixing.PQCiphertext, 0, len(prs)),
			MyIndex:        p.myVk,
		}
		for _, ct := range recoveredCTs {
			revealed.Ciphertexts = append(revealed.Ciphertexts, ct[p.myVk])
		}
		sharedSecrets, err := p.kx.SharedSecrets(revealed,
			sesRun.sid[:], 0, sesRun.mcounts)
		var decapErr *mixing.DecapsulateError
		if errors.As(err, &decapErr) {
			submittingID := p.id
			sesRun.logf("blaming %x for unrecoverable secrets", submittingID[:])
			blamed = append(blamed, *submittingID)
			continue
		}
		if err != nil {
			return err
		}
		p.srKP = sharedSecrets.SRSecrets
		p.dcKP = sharedSecrets.DCSecrets

		for j, m := range p.srMsg {
			// Recover SR pads and mix with committed messages
			pads := mixing.SRMixPads(p.srKP[j], starts[i]+uint32(j))
			srMix := mixing.SRMix(m, pads)

			// Blame when committed mix does not match provided.
			for k := range srMix {
				if srMix[k].Cmp(scratch.SetBytes(p.sr.DCMix[j][k])) != 0 {
					sesRun.logf("blaming %x for bad SR mix", p.id[:])
					blamed = append(blamed, *p.id)
					continue SRLoop
				}
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	// If no roots were solved, but blaming has made it this far,
	// something is quite wrong (or secrets messages were invalidly
	// published).
	if len(sesRun.roots) == 0 {
		c.logerrf("Blame failed: unknown cause of root solving error")
		return nil
	}

	rootSlots := make(map[string]uint32)
	for i, m := range sesRun.roots {
		rootSlots[string(m.Bytes())] = uint32(i)
	}
DCLoop:
	for i, p := range sesRun.peers {
		// This also covers the case of a peer publishing solutions
		// for failing to solve roots, where there is nothing invalid
		// about the roots.  They would not have submitted any DC
		// messages yet in such case.  However, the "blaming $identity
		// for false failure accusation" (handled by an earlier
		// deferred function) if no peers could be assigned blame is
		// not likely to be seen under this situation.
		if p.dc == nil {
			sesRun.logf("blaming %x for missing messages", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		// With the slot reservation successful, no peers should have
		// notified failure to find their slots in the next (DC)
		// message, and there must be mcount DC-net vectors.
		mcount := p.pr.MessageCount
		if uint32(len(p.dc.DCNet)) != mcount {
			sesRun.logf("blaming %x for missing DC mix vectors", p.id[:])
			blamed = append(blamed, *p.id)
			continue
		}

		for j, m := range p.dcMsg {
			srMsg := p.srMsg[j]
			slot, ok := rootSlots[string(srMsg.Bytes())]
			if !ok {
				// Should never get here after a valid SR mix
				return fmt.Errorf("blame failed: no slot for message %v", m)
			}

			// Recover DC pads and mix with committed messages
			pads := mixing.DCMixPads(p.dcKP[j], starts[i]+uint32(j))
			dcMix := mixing.DCMix(pads, m[:], slot)

			// Blame when committed mix does not match provided.
			for k := 0; k < len(dcMix); k++ {
				if !dcMix.Equals(mixing.Vec(p.dc.DCNet[j])) {
					sesRun.logf("blaming %x for bad DC mix", p.id[:])
					blamed = append(blamed, *p.id)
					continue DCLoop
				}
			}
		}
	}
	if len(blamed) > 0 {
		return blamed
	}

	// Blame peers whose unmixed data became invalid since the initial pair
	// request.
	// if j, ok := c.mix.(Joiner); ok {
	// 	// Validation occurs in parallel as it may involve high latency.
	// 	var mu sync.Mutex // protect concurrent appends to blamed
	// 	var wg sync.WaitGroup
	// 	wg.Add(len(c.clients))
	// 	for i := range c.clients {
	// 		i := i
	// 		pr := c.clients[i].pr
	// 		go func() {
	// 			err := j.ValidateUnmixed(pr.Unmixed, pr.MessageCount)
	// 			if err != nil {
	// 				mu.Lock()
	// 				blamed = append(blamed, i)
	// 				mu.Unlock()
	// 			}
	// 			wg.Done()
	// 		}()
	// 	}
	// 	wg.Wait()
	// }
	// if len(blamed) > 0 {
	// 	return blamed
	// }

	return nil
}
