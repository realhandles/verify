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
