# @realhandles/verify

Independently verify [RealHandles](https://realhandles.com) identity proofs.

A RealHandles proof is a JSON file signed by an Ed25519 key that only the owner
holds. This package checks that signature. It is the trust-critical core of
RealHandles, extracted verbatim so **you never have to trust, or even reach,
realhandles.com to verify a proof.** That is the whole point: the key is the
identity, not any server, domain, or company.

- Isomorphic: the same code runs in a browser, a serverless function, or a CLI.
- Dependency-light: [`jose`](https://github.com/panva/jose) only.
- No network calls: verification is pure. You fetch the proof; this checks it.

## Install

```bash
npm install @realhandles/verify
```

## Verify a proof

Every public profile publishes its signed proof at
`https://realhandles.com/<username>/realhandles.json`.

```ts
import { verifySignedManifest } from '@realhandles/verify';

const file = await fetch('https://realhandles.com/dvk/realhandles.json').then((r) => r.json());

const result = await verifySignedManifest(file);
if (result.valid) {
  console.log('Verified. keyId:', result.keyId);
  for (const a of result.manifest!.accounts) {
    console.log(`${a.handle} on ${a.platform} (${a.method})`);
  }
} else {
  console.error('Not valid:', result.reason);
}
```

`verifySignedManifest` decodes the compact JWS in `file.jws`, checks the EdDSA
signature against the public key embedded in the payload, and confirms the
`keyId` is the fingerprint of that key. The mirrored `manifest` JSON is never
trusted over the signature-verified payload.

### Pin a key (the real trust decision)

Verifying that a file is well-signed is not the same as verifying it is signed
by the key **you already trust**. Pass an `expectedKeyId` to require it:

```ts
const result = await verifySignedManifest(file, trustedKeyId);
// result.valid is false if the proof is signed by any other key.
```

This is what makes a lapsed or hijacked domain harmless: verification follows
the key, never the name.

## Verify a whole history (`verifyChain`)

An identity's manifests form an append-only chain: each entry carries `seq` and
`prev` (the hash of the previous entry's JWS). Fetch the history from
`https://realhandles.com/<handle>/realhandles-chain.json` and check all of it at
once:

```ts
const { versions } = await fetch('https://realhandles.com/david/realhandles-chain.json').then((r) => r.json());
const result = await verifyChain(versions.map((v) => v.file), pinnedGenesisKeyId);
// result.keyId is the CURRENT key, proven from the one you originally pinned.
```

Pass the key you pinned the FIRST time you saw the identity. `verifyChain`
confirms every entry is signed, that `seq` and `prev` link up, and that the
signing key only ever changed in a way the identity itself authorized.

### How a key is allowed to change

Two ways, and one of them must hold or the chain is rejected:

- **Rotation.** The entry carries `rotation.prevKeySig`, the OLD key's signature
  over `rotationStatement(newKeyId, seq, prev)`. Used when the holder still has
  their key. Someone who steals only the new key cannot forge this.
- **Recovery.** The old key is gone, so it cannot sign anything. The entry
  carries `rotation.recovery`, signatures over
  `recoveryStatement(newKeyId, seq, prev)` from keys the identity DESIGNATED IN
  ADVANCE via a `recovery` policy in an earlier signed manifest. The policy names
  the permitted keys and how many must agree (`threshold`), so one printed
  recovery key is `{ threshold: 1 }` and recovery contacts are the same shape with
  a higher threshold.

The policy that counts is the one published BEFORE the recovery, never the one
the recovering entry declares about itself. Otherwise anyone could turn up
asserting their own key had been authorized all along.

Note what is absent from both paths: there is no way for a server, a login, or a
domain to authorize a key change. Recovery is still keys all the way down, which
is why this library can check it without asking realhandles.com anything.

## Derive a did:key

Every RealHandles key is also a standard [`did:key`](https://w3c-ccg.github.io/did-method-key/):

```ts
import { jwkToDidKey } from '@realhandles/verify';

const did = jwkToDidKey(result.manifest!.subject.publicKey);
// "did:key:z6Mk..."
```

## Handle-reservation rules

The same isomorphic rules RealHandles uses to decide who may claim a short
(scarce) handle are exported too, so tooling can preview or audit them:

```ts
import { evaluateClaim, computeTrustScore } from '@realhandles/verify';

evaluateClaim('dvk', proofs).qualifies; // boolean
computeTrustScore(proofs).score;        // 0-100
```

## What "verified" means

The proof distinguishes two tiers, and this package exposes both
(`isVerifiedMethod`):

- **Verified**: first-party or handle-bound methods (OAuth, an author-bound
  post, a platform API lookup, domain control, or a mutual `rel="me"` link).
- **Claimed**: a self-asserted account the owner signed but no third party
  confirmed.

Both are covered by the signature. The distinction is about how the account
control was established, not about whether the file is authentic.

## Spec and schema

The wire format is documented in the [RealHandles protocol spec](https://github.com/realhandles/spec),
with a JSON Schema at `https://realhandles.com/schema/realhandles-v1.json`. This
package is the reference implementation of the verification half of that spec.

## License

MIT
