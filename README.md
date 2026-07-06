# FallTrust

**Web-of-trust attestations.** Signed vouches about identities. No central authority. No consensus. Just a graph of who trusts whom, and by how much.

Live demo: https://sjgant80-hub.github.io/falltrust/

## What it does

You sign a statement: *"I, DID X, attest that DID Y is Thomas — strength 0.9."*
Your peers do the same about who they know. Trust becomes transitive:

- If you trust Simon at 1.0, and Simon trusts Thomas at 0.9,
- FallTrust extends **0.9** trust to Thomas without asking anyone's permission.
- Strengths multiply along the path. Longer chains decay.

This is enough for:

- Spam filtering (require a trust score above threshold)
- Sybil resistance (fake identities have no vouches from real people)
- Peer relay authorization (only relay for people you transitively trust)
- Human-scale reputation (small, local, honest)

## How it works

- **Signing** — every vouch is signed with your FallID key. Anyone can verify authorship.
- **Storage** — vouches live in your browser's IndexedDB. Nothing leaves your device unless you gossip it.
- **Gossip** — optional FallLink integration lets you share vouches with peers. Or export/import JSON manually.
- **Scoring** — BFS from your DID, picking the highest-scoring path (product of strengths) to any target, up to `maxDepth` hops (default 3).

## API

```js
import { FallTrust } from './falltrust.js';

const ft = new FallTrust({ fallidInstance: myFallID, falllinkInstance: myFallLink });

// Sign an attestation
await ft.vouch('did:key:z6Mk…', 'This is Thomas', 0.9);

// Revoke it later
await ft.revoke('did:key:z6Mk…');

// How much do I transitively trust some DID?
const { score, path } = await ft.trustScore('did:key:z6Mk…', 3);

// Who has vouched for me?
const rx = await ft.listReceivedVouches();

// Merge attestations from a peer
await ft.importVouches(peerJson.vouches);

// Local view of the graph
const g = await ft.graph();
```

## Not a blockchain

There is no chain, no consensus, no token. Vouches are local documents you choose to share. Anyone can lie in a vouch, but they can't lie in your name — signatures block that. What survives is a graph of small honest opinions.

## License

MIT · AI-Native Solutions · 2026
