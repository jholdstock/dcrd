Package mixclient implements the client side of the Decred mixing protocol,
a DiceMix Light variant that produces a coinjoin transaction from the mixed
outputs of several mutually distrusting peers.

The design derives from two documents, both kept in the repository root:

	ruffing2016.pdf  "P2P Mixing and Unlinkable Bitcoin Transactions" by Tim
	                 Ruffing, Pedro Moreno-Sanchez and Aniket Kate (NDSS'17),
	                 which introduces the DiceMix P2P mixing protocol and
	                 CoinShuffle++, its application to Bitcoin coinjoins.
	protocol.md      The DiceMix Light working draft, a simplification of
	                 DiceMix by the same authors.  It trades DiceMix's 4+2f
	                 communication rounds for 4+3f in the presence of f
	                 disrupting peers, in exchange for far less computation
	                 and a simpler protocol.

The mixing performed here is DiceMix Light applied to Decred coinjoins,
following CoinShuffle++ in using the signing of a coinjoin transaction as the
confirmation subprotocol.  Credit for the underlying cryptographic design,
including the exponential-encoding slot reservation, the recovery of messages
from power sums via Newton's identities, and the reveal-and-replay approach to
blame assignment, belongs to those authors.  The deviations described below
are Decred's.

# Message sequence

A successful mix publishes the following messages, in this order.  Each is a
wire message broadcast to all peers through the mixpool rather than sent to
any individual peer.

	PR  mixpairreq   Pair request.  Describes the type of coinjoin desired,
	                 the unmixed inputs and change being contributed, and
	                 proof of the ability to sign the resulting coinjoin.
	                 Peers with compatible PRs form a pairing.
	KE  mixkeyxchg   Key exchange.  Publishes the peer's session ECDH and
	                 SNTRUP4591761 public keys, along with a commitment to
	                 the secrets that must be revealed if the run fails.
	                 The set of KEs referencing a common PR set forms a
	                 session, identified by a session ID.
	CT  mixcphrtxt   Ciphertexts.  SNTRUP4591761 ciphertexts encapsulated to
	                 every other peer's published PQ public key, from which
	                 pairwise shared keys are derived.
	SR  mixslotres   Slot reservation.  The exponential DC-net vectors used
	                 to anonymously reserve each peer's slot in the mix.
	                 Summing all SRs yields the power sums of a polynomial
	                 whose roots are the reserved slot numbers.
	FP  mixfactpoly  Factored polynomial (conditional).  The solved roots of
	                 the slot reservation polynomial, published by peers
	                 capable of factoring it so that peers which are not can
	                 still proceed.  Sent alongside DC, not as a separate
	                 stage.
	DC  mixdcnet     DC-net.  The XOR DC-net vectors carrying each peer's
	                 mixed output in its reserved slot.  XORing all DCs
	                 reveals every mixed output without revealing which peer
	                 contributed which.
	CM  mixconfirm   Confirm.  The peer's signatures over the assembled
	                 coinjoin.  Once all CMs are received the signatures are
	                 merged and the transaction is published, completing the
	                 session.

Each message after PR references the hashes of the previous stage's messages
it observed, chaining the run together and ensuring peers agree on the set of
participants at every stage.

# Failure and blame

	RS  mixsecrets   Reveal secrets.  Broadcast out of sequence when a run
	                 fails, exposing the secrets committed to in the KE.

RS is not part of the successful path.  When a peer detects misbehaviour, or a
stage deadline passes without every expected message arriving, all peers reveal
their secrets so that the faulty peers can be identified from the revealed
values, excluded, and the session rerun with the remaining peers.  A rerun
starts again from KE; the PRs are reused.

# Timing

Sessions are aligned to epochs.  PRs are deliberately not published within
+/-30s of an epoch and carry added jitter, and the final coinjoin broadcast is
similarly delayed, both to frustrate deanonymization by publication timing.
Each stage has a receive deadline derived from the epoch; missing it moves the
session into blame assignment rather than failing it outright.

# Differences from the published protocols

Readers coming from either document should be aware of the following
divergences.

No bulletin board.  Both documents assume peers communicate through a
terminating reliable broadcast mechanism (a bulletin board) which guarantees
that every peer sees the same message and which notifies peers when someone
fails to send in time.  There is no such component here.  Messages are
broadcast over the Decred P2P network and collected from the mixpool, and the
missing-message notification is replaced by the epoch-derived receive deadline
on each stage.  Equivocation is instead made detectable by having every
message reference the hashes of the previous stage's messages it observed, so
peers that were shown different views disagree on those hashes and the session
fails into blame assignment.

Different meaning for CM.  In DiceMix (see Fig. 2 of the paper) the rounds are
KE, CM, DC, SK, RV and CF, where CM is the *commitment* round and CF is the
confirmation.  Here CM is the *confirm* message, corresponding to the paper's
CF.  The commitment has no round of its own; it is carried in the KE, matching
DiceMix Light, which folds it into the key exchange.  Likewise the paper's
separate SK (reveal secret key) and RV (reveal pads) rounds are combined into
the single RS message.

An extra round for post-quantum key exchange.  Both documents specify a
non-interactive key exchange, from which every pairwise shared key follows
from the published public keys alone.  This implementation additionally
performs SNTRUP4591761 encapsulation alongside secp256k1 ECDH, so that shared
secrets remain secret against an attacker with a quantum computer.  A KEM is
not non-interactive, so the ciphertexts must be published in a round of their
own.  The CT message exists solely for this and has no counterpart in either
document; it is the reason a run here has one more round than DiceMix Light
describes.

Delegated root finding.  Recovering the slot reservations requires factoring
the polynomial recovered from the power sums.  The documents treat this as
something every peer does.  Here a peer may advertise that it cannot solve
roots, in which case it relies on the FP message published by a peer that can.
This is an accommodation for constrained clients, not a change to the
cryptography.

In-band pairing.  The paper explicitly treats the discovery of mixing partners
as an orthogonal bootstrapping mechanism outside its scope, and assumes peers
already know each other's verification keys.  The PR message is that
bootstrapping, performed in band over the same P2P network.

Timing defences.  Section VIII of the paper describes a deanonymization attack
in which a network attacker partitions one honest peer, the remaining peers
conclude it is offline and exclude it, and the next run then reveals which
message was the excluded peer's.  The paper's stated resolution is for peers
to mix fresh, uncorrelated input messages in every run, which is done here by
regenerating a peer's session keys and messages on rerun.  The epoch alignment
and the publication jitter applied to PRs and to the final coinjoin broadcast
address a related concern that the documents do not have to: with no bulletin
board interposed between peers, the time at which a message reaches the
network is itself observable and must not correlate messages belonging to the
same peer.
