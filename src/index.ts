// @realhandles/verify - independently verify RealHandles identity proofs.
//
// The three modules are the trust-critical core of RealHandles, extracted
// verbatim so anyone can verify a proof without trusting (or even reaching)
// realhandles.com:
//   - manifest: JWS/Ed25519 verification + the signed-manifest types.
//   - didkey:   derive a standard did:key from the Ed25519 public key.
//   - handles:  the handle-reservation gate and trust-score rules.
export * from './manifest.js';
export * from './didkey.js';
export * from './handles.js';
