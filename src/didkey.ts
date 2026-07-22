// did:key derivation from an Ed25519 public key.
//
// Your signing key already IS a decentralized identifier. This encodes the
// public key as a standard did:key (multicodec ed25519-pub 0xed01 + multibase
// base58btc, 'z' prefix), which is free, deterministic, and interoperable with
// the DID / verifiable-credentials ecosystem (and did:plc / Bluesky-style
// tooling). No blockchain, no cost, no dependency. This is the "web3 bridge":
// the identity is portable into that world without wallets or gas.

import type { JWK } from 'jose';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function fromB64u(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base58btc(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (const b of bytes) {
    if (b === 0) out += '1';
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58[digits[i]];
  return out;
}

/** did:key string for an Ed25519 public JWK, or null if the key is not Ed25519. */
export function jwkToDidKey(jwk: JWK): string | null {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) return null;
  const pub = fromB64u(jwk.x);
  if (pub.length !== 32) return null;
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed[0] = 0xed; // multicodec: ed25519-pub
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);
  return 'did:key:z' + base58btc(prefixed);
}
