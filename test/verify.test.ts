import { describe, it, expect } from 'vitest';
import { CompactSign, generateKeyPair, exportJWK } from 'jose';
import {
  verifySignedManifest,
  keyIdFromJwk,
  jwkToDidKey,
  evaluateClaim,
  MANIFEST_VERSION,
  SIGNING_ALG,
  type Manifest,
} from '../src/index.js';

// Build and sign a real manifest with a fresh Ed25519 key, mirroring how the
// RealHandles client signs. This exercises the full verify path end to end.
async function makeSignedManifest(over: Partial<Manifest> = {}) {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const keyId = await keyIdFromJwk(publicJwk);
  const manifest: Manifest = {
    version: MANIFEST_VERSION,
    subject: { username: 'dvk', displayName: 'David', publicKey: publicJwk, keyId },
    accounts: [
      { platform: 'github', handle: 'davidvkimball', profileUrl: 'https://github.com/davidvkimball', method: 'oauth', verifiedAt: '2026-01-01T00:00:00.000Z' },
    ],
    issued: '2026-01-01T00:00:00.000Z',
    statement: 'These accounts belong to the holder of this key.',
    ...over,
  };
  const jws = await new CompactSign(new TextEncoder().encode(JSON.stringify(manifest)))
    .setProtectedHeader({ alg: SIGNING_ALG, kid: keyId })
    .sign(privateKey);
  return { jws, keyId, publicJwk, manifest };
}

describe('verifySignedManifest', () => {
  it('accepts a manifest signed by its embedded key', async () => {
    const { jws, keyId } = await makeSignedManifest();
    const r = await verifySignedManifest({ jws });
    expect(r.valid).toBe(true);
    expect(r.keyId).toBe(keyId);
    expect(r.manifest?.subject.username).toBe('dvk');
  });

  it('pins a key: rejects a valid manifest signed by a different key', async () => {
    const { jws } = await makeSignedManifest();
    const r = await verifySignedManifest({ jws }, 'a-key-you-do-not-trust');
    expect(r.valid).toBe(false);
  });

  it('rejects a tampered signature (payload intact, signature broken)', async () => {
    const { jws } = await makeSignedManifest();
    const [h, p, s] = jws.split('.');
    const badSig = s.slice(0, -3) + (s.endsWith('aaa') ? 'bbb' : 'aaa');
    const r = await verifySignedManifest({ jws: [h, p, badSig].join('.') });
    expect(r.valid).toBe(false);
  });

  it('rejects a malformed JWS', async () => {
    const r = await verifySignedManifest({ jws: 'not-a-jws' });
    expect(r.valid).toBe(false);
  });
});

describe('did:key and handle rules are re-exported', () => {
  it('derives a standard did:key from the subject key', async () => {
    const { publicJwk } = await makeSignedManifest();
    const did = jwkToDidKey(publicJwk);
    expect(did?.startsWith('did:key:z')).toBe(true);
  });

  it('exposes the handle-reservation gate', () => {
    // A long handle with no proofs is open to claim.
    expect(evaluateClaim('averylonghandle', []).qualifies).toBe(true);
    // A 1-2 character handle is reserved and needs a strong matching proof.
    expect(evaluateClaim('dv', []).qualifies).toBe(false);
  });
});
