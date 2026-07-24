import { describe, it, expect } from 'vitest';
import { CompactSign, generateKeyPair, exportJWK } from 'jose';
import {
  verifySignedManifest,
  keyIdFromJwk,
  jwkToDidKey,
  evaluateClaim,
  MANIFEST_VERSION,
  SIGNING_ALG,
  verifyChain,
  manifestJwsHash,
  recoveryStatement,
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

// --- recovery (v0.5.0) -----------------------------------------------------
// A designated key taking over a lost identity is the one case where authority
// does not come from the previous key, so it gets checked from the outside here,
// through the published package, exactly as a third party would use it.
describe('verifyChain: recovery', () => {
  async function key() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    const publicJwk = await exportJWK(publicKey);
    return { privateKey, publicJwk, keyId: await keyIdFromJwk(publicJwk) };
  }
  type K = Awaited<ReturnType<typeof key>>;

  async function entry(k: K, over: Partial<Manifest>) {
    const manifest: Manifest = {
      version: MANIFEST_VERSION,
      subject: { username: 'dvk', publicKey: k.publicJwk, keyId: k.keyId },
      accounts: [],
      issued: '2026-01-01T00:00:00.000Z',
      statement: 'x',
      seq: 0,
      prev: null,
      ...over,
    };
    const jws = await new CompactSign(new TextEncoder().encode(JSON.stringify(manifest)))
      .setProtectedHeader({ alg: SIGNING_ALG, kid: k.keyId })
      .sign(k.privateKey);
    return { jws };
  }

  const policy = (k: K) => ({ threshold: 1, keys: [{ keyId: k.keyId, publicKey: k.publicJwk, label: 'printed recovery key' }] });

  async function approve(k: K, newKeyId: string, seq: number, prev: string | null) {
    return new CompactSign(new TextEncoder().encode(recoveryStatement(newKeyId, seq, prev)))
      .setProtectedHeader({ alg: SIGNING_ALG, kid: k.keyId })
      .sign(k.privateKey);
  }

  it('transfers trust to a new key approved by the designated recovery key', async () => {
    const lost = await key();
    const rec = await key();
    const fresh = await key();
    const gen = await entry(lost, { recovery: policy(rec) });
    const prev = await manifestJwsHash(gen.jws);
    const sig = await approve(rec, fresh.keyId, 1, prev);
    const recovered = await entry(fresh, { seq: 1, prev, rotation: { recovery: [{ keyId: rec.keyId, sig }] }, recovery: policy(rec) });

    const r = await verifyChain([gen, recovered], lost.keyId); // pin the original key
    expect(r.valid).toBe(true);
    expect(r.keyId).toBe(fresh.keyId);
  });

  it('rejects a recovery the identity never authorized', async () => {
    const lost = await key();
    const attacker = await key();
    const fresh = await key();
    const gen = await entry(lost, {}); // designated nobody
    const prev = await manifestJwsHash(gen.jws);
    const sig = await approve(attacker, fresh.keyId, 1, prev);
    // The attacker also writes their own policy into the entry. It must not count.
    const forged = await entry(fresh, { seq: 1, prev, rotation: { recovery: [{ keyId: attacker.keyId, sig }] }, recovery: policy(attacker) });
    expect((await verifyChain([gen, forged])).valid).toBe(false);
  });
});
