// The signed manifest: the portable, self-verifying root of trust.
//
// This module is isomorphic (browser + server). It has no Node-only or
// DOM-only imports so the exact same verification runs in the dashboard, in a
// serverless function, on the independent /verify page, and in anyone else's
// tooling. `jose` is the only dependency and it verifies EdDSA (Ed25519) with
// off-the-shelf, standards-based code.
//
// WHY A JWS: the authoritative artifact is a compact JWS whose payload is the
// manifest. The signature proves the holder of the private key produced this
// exact manifest. Verification never asks "does a file exist at a domain"; it
// asks "is this signed by the key we already trust." That is the whole idea:
// the key is the identity, the domain is just one anchor the key points at.

import { compactVerify, importJWK, type JWK } from 'jose';

// Re-exported so callers that already depend on this module for manifest types
// do not have to reach into jose separately for the one type those types are
// built out of.
export type { JWK };

export const MANIFEST_VERSION = '1';
export const SIGNING_ALG = 'EdDSA'; // Ed25519

export interface ClaimedAccount {
  platform: string; // e.g. "github", "x", "domain"
  handle: string; // username on that platform, or the domain
  profileUrl: string;
  method: 'oauth' | 'domain-anchor' | 'proof-post';
  verifiedAt: string; // ISO 8601
  // The platform's own IMMUTABLE id for this account, where the verification had
  // one to record (GitHub/Discord/Twitch/GitLab/Dribbble account ids, a Bluesky
  // DID, a nostr pubkey). The handle beside it is a mutable LABEL.
  //
  // WHY IT IS SIGNED. A handle can change hands. Verify x:cursor today, and when
  // the name later moves to somebody else nothing about a handle-bound record
  // notices: the manifest still says `cursor`, the profile still reads Verified,
  // and we publish a verified link to a stranger's account. Signing the id makes
  // that drift detectable rather than merely dateable, because the id and the
  // handle can then be compared against what the server verified. See
  // lib/crosscheck.ts, which decides what a disagreement means.
  //
  // OPTIONAL, and permanently so. Absent means "verified before we recorded
  // this, or by a method that has no id at all", never "suspect". A posted
  // token, a bio token and a mutual rel="me" page carry only a handle and a URL,
  // so those accounts stay handle-bound; do not read an absent id as a mismatch.
  // Additive to the wire format on purpose: every manifest signed before this
  // field existed still verifies unchanged, since verification checks the
  // signature over the payload bytes and never rejects a field it does not know.
  accountId?: string;
  // For accounts that are an organization or a server the person owns/runs
  // rather than a personal profile: what it is, and its own logo/icon. Lets a
  // reader tell "the lilAgents GitHub org" apart from "a person named lilagents".
  entity?: 'organization' | 'server';
  image?: string; // org/server avatar URL
  // For a link-in-bio (rel="me") account: the builder that made the page, when
  // it is a recognized partner (e.g. "lilhub"). Cosmetic only, so a reader sees
  // "Link-in-bio · lilHub" instead of a raw host. Never a trust signal.
  builder?: string;
}

export interface Anchor {
  url: string; // where the signed anchor file is hosted
  kind: 'domain' | 'gist' | 'other';
  domain?: string; // for a domain anchor, the domain itself
}

// The inverse of an account claim: a signed statement that something is NOT you.
// 'account' calls out a specific impersonator or a same-name person; 'platform'
// declares you are never on a platform, so any account there claiming to be you
// is fake. Additive to the key model: still just signed statements by your key.
export interface Disavowal {
  kind: 'account' | 'platform';
  platform: string; // e.g. "x", "tiktok"
  handle?: string; // the impersonating handle (account kind)
  url?: string; // link to the impersonating profile (account kind)
  note?: string; // e.g. "known impersonator", "same name, different person"
}

// The catch-all counterpart to a Disavowal, and a different KIND of claim.
//
// A Disavowal is OPEN-world: "that one account is not me", saying nothing about
// accounts nobody has named. This is CLOSED-world: "the list you are looking at
// is the whole list". That is the assertion that actually defeats impersonation
// at scale, because disavowing impersonators one at a time loses to whoever can
// register accounts faster, while declaring the list complete makes an unlisted
// account suspect by default rather than merely unverified.
//
// It is also far easier to be wrong about. A forgotten old account, or one
// opened tomorrow, makes an unqualified "anything not listed is not me" false
// the moment it is signed. So this is a COMPLETENESS claim carrying its own
// date, never an absolute denial: it says the list was whole as of `asserted`,
// which stays true afterwards and lets a reader judge how fresh it is.
//
// `asserted` is the date the owner last AFFIRMED the list was whole, not the
// date of the last publish. Carry it forward verbatim on an ordinary re-sign
// instead of restamping it: restamping would refresh the date on every unrelated
// edit and make staleness invisible again, which is the one failure this shape
// exists to prevent.
export interface ListCompleteness {
  complete: boolean; // true: `accounts` is declared exhaustive as of `asserted`
  asserted: string; // ISO 8601, when the owner last affirmed it
  note?: string; // optional qualifier from the owner, e.g. "public accounts only"
}

/**
 * A completeness claim is only publishable if it is dated. An undated one reads
 * as an unqualified denial ("anything not listed is not me"), which is the exact
 * claim this field exists to avoid, so a missing or unparseable `asserted` makes
 * it invalid rather than merely untidy. Exported so the server enforces the same
 * rule the profile page renders.
 */
export function isValidCompleteness(c: ListCompleteness | undefined): c is ListCompleteness {
  if (!c || typeof c !== 'object') return false;
  if (typeof c.complete !== 'boolean') return false;
  if (typeof c.asserted !== 'string' || Number.isNaN(Date.parse(c.asserted))) return false;
  if (c.note !== undefined && typeof c.note !== 'string') return false;
  return true;
}

function formatCompletenessDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

/** Reader-facing wording for a dated completeness claim (boilerplate only; note is separate). */
export function completenessStatement(c: ListCompleteness, subject: 'person' | 'organization'): string {
  const date = formatCompletenessDate(c.asserted);
  return subject === 'organization'
    ? `As of ${date}, every account we publish on this profile is listed below.`
    : `As of ${date}, every account I publish on this profile is listed below.`;
}

/** Short clarifier shown under the statement; not part of the signed claim. */
export function completenessClarifier(): string {
  return 'Accounts not shown here are not part of this published list. That does not by itself mean they are impersonators.';
}

/** Label for the optional owner-written note on profile and verify pages. */
export function completenessNoteLabel(subject: 'person' | 'organization'): string {
  return subject === 'organization' ? 'In our words' : 'In my words';
}

// Whether the owner wants this identity PUBLISHED. It is in the signed manifest,
// and that placement is the whole design: the key authorizes hiding, so a stolen
// login cannot take someone's profile down, for exactly the reason a login
// cannot rename or delete one.
//
// Read the word narrowly. 'private' is a request not to PUBLISH, never a claim
// of erasure, and the copy around it must say so:
//
//  - We stop serving the profile page, realhandles.json, the OG card, and the
//    directory listing. That is the part we control and can honor.
//  - The signed history at /<handle>/realhandles-chain.json KEEPS SERVING.
//    Withholding verification data because someone asked would make us the
//    gatekeeper of who can be verified, which is the one role this product
//    exists to refuse, and every version's hash is already committed to Bitcoin
//    by OpenTimestamps, so erasure is a promise we could not keep even if we
//    wanted to make it.
//  - A verifier reading the chain therefore sees a signed statement that the
//    owner asked for privacy, and can choose to respect it. That is a better
//    outcome than a 404, which tells a reader nothing and would look identical
//    to us having lost the data.
//
// Absent means public. Every manifest signed before this field existed omits it,
// and the safe reading of an absent field is the state those identities are
// already in.
export type Visibility = 'public' | 'private';

/**
 * Exported so the server enforces the same values it publishes. Anything other
 * than these two is refused at POST /api/manifest rather than stored and
 * guessed about later: a visibility nobody can interpret is worse than none,
 * because the guess decides whether a real person's page is up.
 */
export function isValidVisibility(v: unknown): v is Visibility {
  return v === 'public' || v === 'private';
}

/**
 * Should this manifest be published? Reads the SIGNED payload, never the mirror.
 *
 * Fails closed on anything it does not recognize. An unknown value means the
 * owner signed a request we do not implement (a future 'unlisted', say), and the
 * conservative answer to "publish this person or not" is no. Only the owner's
 * own key can put a value here, so failing closed can never be used against
 * them by anyone else.
 *
 * Its caller `isHiddenJws` in lib/visibility.ts fails OPEN, and the two pointing
 * opposite ways is deliberate, not an inconsistency to tidy up. The difference
 * is what the input can prove. Here the input is a manifest whose signature was
 * checked, so an odd value is a statement the owner MADE and gets the reading
 * that respects it. There the input is a string that would not decode at all,
 * which is no statement about anybody, and treating it as a request to hide
 * would take profiles down over a parse failure. Change one and you must decide
 * about the other; do not make them match for symmetry.
 */
export function isHiddenManifest(m: { visibility?: unknown } | null | undefined): boolean {
  const v = m?.visibility;
  if (v === undefined || v === null) return false;
  return v !== 'public';
}

// A "pointer" anchor file: signed once, hosted once, never needs updating. It
// proves control of the host location and points to the canonical (always
// current) proof at RealHandles. Trades the fully-offline guarantee of a hosted
// full manifest for zero maintenance.
export interface PointerPayload {
  version: string;
  type: 'anchor-pointer';
  keyId: string;
  publicKey: JWK;
  canonical: string; // https://realhandles.com/<user>/realhandles.json
  issued: string;
}

export interface PointerFile {
  $schema: string;
  jws: string;
  pointer: PointerPayload;
  publicKeyJwk: JWK;
  keyId: string;
}

// A key rotation: this manifest is signed by a NEW key, and the rotation carries
// proof that the change was authorized. Continuity follows the key: a verifier
// that trusted the old key accepts the new one because something the old key had
// already vouched for says so.
//
// TWO ways to authorize, and exactly one of them must hold:
//
//  1. `prevKeySig`: the OLD key itself signs the handoff. The normal case, used
//     when you still hold your key and simply want a new one.
//  2. `recovery`: signatures from keys the identity DESIGNATED in advance (see
//     RecoveryPolicy), for when the old key is gone and cannot sign anything.
//     This is what makes a lost key survivable without handing anyone else
//     standing authority over the identity: the designation was itself signed by
//     the user's own key, back when they still had it, so the authority is
//     inherited from the root of trust rather than granted by us.
//
// What is deliberately NOT here: any path where a server, a login, or a domain
// can authorize a key change. Recovery is still keys all the way down.
export interface Rotation {
  prevKeyId?: string; // keyId of the key being rotated away from (path 1)
  prevKeySig?: string; // compact JWS by the previous key over rotationStatement(...)
  recovery?: RecoverySignature[]; // signatures by designated recovery keys (path 2)
}

/** One designated recovery key's authorization of a specific key change. */
export interface RecoverySignature {
  keyId: string; // which designated key signed (must appear in the policy in force)
  sig: string; // compact JWS by that key over recoveryStatement(...)
}

/** A key the identity has authorized, in advance, to recover it. */
export interface RecoveryKey {
  keyId: string;
  publicKey: JWK; // embedded so a verifier can check a recovery offline
  label?: string; // e.g. "printed recovery key", or a contact's handle
}

// Who may recover this identity if the signing key is lost, declared inside the
// SIGNED manifest so it carries the user's own authority and is public.
// `threshold` of the listed keys must sign. One printed key is {threshold: 1,
// keys: [that key]}; recovery contacts are the same shape with a higher
// threshold and other people's keys, which is why this is a policy and not a
// single field.
//
// Honest consequence, and it must be surfaced in any UI: a designated key is as
// powerful as the signing key. Whoever holds enough of them can take the
// identity. Threshold is the only dial that makes that harder.
export interface RecoveryPolicy {
  threshold: number;
  keys: RecoveryKey[];
}

// The exact bytes the PREVIOUS key signs to authorize a rotation to `newKeyId` at
// a given chain position. Signer and verifier must agree on this string.
export function rotationStatement(newKeyId: string, seq: number, prev: string | null): string {
  return `rh-rotate:v1:${newKeyId}:${seq}:${prev ?? ''}`;
}

// The bytes a designated RECOVERY key signs. Deliberately a different string
// from rotationStatement: domain separation stops a signature collected for one
// purpose being replayed as the other.
export function recoveryStatement(newKeyId: string, seq: number, prev: string | null): string {
  return `rh-recover:v1:${newKeyId}:${seq}:${prev ?? ''}`;
}

/** A policy is only meaningful if enough distinct keys exist to meet it. */
export function isValidRecoveryPolicy(p: RecoveryPolicy | undefined): p is RecoveryPolicy {
  if (!p || !Array.isArray(p.keys) || p.keys.length === 0) return false;
  if (!Number.isInteger(p.threshold) || p.threshold < 1 || p.threshold > p.keys.length) return false;
  const ids = new Set(p.keys.map((k) => k.keyId));
  return ids.size === p.keys.length; // duplicates would inflate the count
}

/**
 * Count how many DISTINCT designated keys validly authorized this key change.
 * Exported so the server can enforce the same rule it publishes.
 */
export async function countRecoveryApprovals(
  policy: RecoveryPolicy,
  sigs: RecoverySignature[],
  newKeyId: string,
  seq: number,
  prev: string | null
): Promise<number> {
  const statement = recoveryStatement(newKeyId, seq, prev);
  const approved = new Set<string>();
  for (const s of sigs ?? []) {
    if (approved.has(s.keyId)) continue; // one key, one vote
    const designated = policy.keys.find((k) => k.keyId === s.keyId);
    if (!designated) continue; // not a key this identity ever authorized
    try {
      const key = await importJWK(designated.publicKey, SIGNING_ALG);
      const { payload } = await compactVerify(s.sig, key);
      if (new TextDecoder().decode(payload) !== statement) continue;
      // The embedded public key must really be the keyId it claims, or a
      // hostile entry could smuggle its own key in under a designated id.
      if ((await keyIdFromJwk(designated.publicKey)) !== designated.keyId) continue;
      approved.add(s.keyId);
    } catch {
      /* bad signature: does not count */
    }
  }
  return approved.size;
}

export interface Manifest {
  version: string;
  subject: {
    username: string;
    displayName?: string;
    publicKey: JWK; // OKP / Ed25519 public JWK
    keyId: string; // stable fingerprint of the public key (see keyIdFromJwk)
  };
  accounts: ClaimedAccount[];
  disavowed?: Disavowal[]; // signed "not me" statements (impersonators, absences)
  listCompleteness?: ListCompleteness; // dated claim that accounts is exhaustive as of asserted
  // Whether the owner wants this identity published. Signed, so hiding takes the
  // key and not merely a session. Absent means public. See Visibility: this is a
  // request not to publish, and the signed history keeps serving regardless.
  visibility?: Visibility;
  anchor?: Anchor; // one rotatable pointer; NOT the identity
  issued: string; // ISO 8601
  statement: string; // human-readable claim
  // Sigchain: position in the identity's signed history + a hash link to the
  // previous manifest, making the history append-only and tamper-evident. Both
  // optional for backward compatibility: a manifest without them is genesis
  // (seq 0, prev null). See verifyChain.
  seq?: number; // 0-based, increments by 1 per re-sign
  prev?: string | null; // base64url(SHA-256(previous manifest JWS)), null at genesis
  rotation?: Rotation; // present only when this entry changes the signing key
  // Who may recover this identity if the signing key is lost. Signed, so it is
  // the user's own key that grants this authority, and public, so anyone
  // verifying can see the recovery model an identity is running under.
  recovery?: RecoveryPolicy;
}

// The file we serve / hand the user to host. `jws` is authoritative; the
// `manifest` field is a convenience mirror for humans and never trusted on its
// own. A verifier decodes `jws` and ignores everything else if they disagree.
export interface SignedManifestFile {
  $schema: string;
  jws: string;
  manifest: Manifest;
  publicKeyJwk: JWK;
  keyId: string;
}

export const SCHEMA_URL = 'https://realhandles.com/schema/realhandles-v1.json';

// --- key id: a stable, portable fingerprint of the public key --------------

const b64u = {
  encode(bytes: Uint8Array): string {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

/**
 * keyId = base64url(SHA-256(canonical Ed25519 public JWK)).
 * Deterministic across platforms because we canonicalize the JWK to exactly
 * {crv,kty,x}. This is the fingerprint verifiers pin ("trust this key").
 */
export async function keyIdFromJwk(jwk: JWK): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return b64u.encode(new Uint8Array(digest));
}

/**
 * base64url(SHA-256(compact JWS)). The next manifest puts this in its `prev`
 * field to chain to this one, making the signed history append-only and
 * tamper-evident: you cannot rewrite a past entry without breaking every hash
 * link that follows it.
 */
export async function manifestJwsHash(jws: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(jws));
  return b64u.encode(new Uint8Array(digest));
}

// --- verification ----------------------------------------------------------

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  manifest?: Manifest;
  keyId?: string;
}

/**
 * Independently verify a signed manifest. Steps, in order:
 *  1. Decode the JWS and check the EdDSA signature against the public key
 *     embedded in the manifest.
 *  2. Recompute the keyId from that public key and confirm it matches the
 *     manifest's claimed keyId and the JWS `kid` header.
 * If `expectedKeyId` is supplied (a key you already trust), we also confirm the
 * signer is that same key. That is the real trust decision: not "is there a
 * file" but "is this the key I trusted before."
 */
export async function verifySignedManifest(
  file: Pick<SignedManifestFile, 'jws'>,
  expectedKeyId?: string
): Promise<VerifyResult> {
  let manifest: Manifest;
  try {
    // Peek the payload to read the embedded public key, then verify against it.
    const payloadB64 = file.jws.split('.')[1];
    if (!payloadB64) return { valid: false, reason: 'Malformed JWS (no payload).' };
    const json = new TextDecoder().decode(fromB64u(payloadB64));
    manifest = JSON.parse(json) as Manifest;
  } catch {
    return { valid: false, reason: 'Could not decode manifest payload.' };
  }

  const pubJwk = manifest?.subject?.publicKey;
  if (!pubJwk || pubJwk.kty !== 'OKP' || pubJwk.crv !== 'Ed25519') {
    return { valid: false, reason: 'Manifest is missing a valid Ed25519 public key.' };
  }

  let payloadBytes: Uint8Array;
  try {
    const key = await importJWK(pubJwk, SIGNING_ALG);
    const { payload } = await compactVerify(file.jws, key);
    payloadBytes = payload;
  } catch {
    return { valid: false, reason: 'Signature does not verify against the manifest public key.' };
  }

  // Re-parse from the *verified* bytes so display never diverges from signed data.
  let verified: Manifest;
  try {
    verified = JSON.parse(new TextDecoder().decode(payloadBytes)) as Manifest;
  } catch {
    return { valid: false, reason: 'Verified payload is not valid JSON.' };
  }

  const computedKeyId = await keyIdFromJwk(verified.subject.publicKey);
  if (verified.subject.keyId !== computedKeyId) {
    return { valid: false, reason: 'keyId does not match the public key.' };
  }
  if (expectedKeyId && expectedKeyId !== computedKeyId) {
    return { valid: false, reason: 'Signed by a different key than the one you trust.', keyId: computedKeyId };
  }

  return { valid: true, manifest: verified, keyId: computedKeyId };
}

export interface ChainResult {
  /** Every entry's signature verified, every link matched, every key change was authorized. */
  valid: boolean;
  /**
   * ...AND the history reaches back to the genesis (seq 0). A chain can be
   * entirely valid yet incomplete, when the entries before its first one are not
   * available. That is a real and separate state: nothing about it is forged, but
   * it cannot prove descent from a key you pinned at the genesis, so it never
   * satisfies `expectedKeyId`. Do not treat `valid` alone as full trust.
   */
  complete: boolean;
  reason?: string;
  keyId?: string;
  length: number;
  /** Chain position of the first entry supplied. 0 for a complete history. */
  startsAt?: number;
}

/**
 * Verify an identity's manifest history is a well-formed append-only chain.
 * Entries must be ordered oldest-first (as served at
 * /<handle>/realhandles-chain.json). Checks that every entry verifies, `seq`
 * increments by 1, and each `prev` equals the hash of the previous entry's JWS.
 * The signing key must stay the same UNLESS an entry carries a valid `rotation`:
 * then the change is accepted because the previous key signed a statement
 * authorizing the new one (continuity follows the key).
 *
 * TWO separate answers come back, and callers must read both. `valid` says the
 * entries supplied are sound. `complete` says they also reach back to the genesis
 * at seq 0. A history whose earliest entries are simply gone is `valid` but not
 * `complete`: every signature in it is genuine, which is a different thing from a
 * forgery and must not be reported as one. Only a complete chain can be checked
 * against a pinned genesis key, so `expectedKeyId` always fails on an incomplete
 * one and no trust decision is loosened by the distinction.
 *
 * `keyId` in the result is the CURRENT key (after any rotations). If
 * `expectedKeyId` is given, it must equal the GENESIS key: you pin a key the
 * first time you see an identity, and the chain proves the current key from it.
 */
export async function verifyChain(
  entries: Pick<SignedManifestFile, 'jws'>[],
  expectedKeyId?: string
): Promise<ChainResult> {
  let trustedKeyId: string | undefined; // the key the chain currently trusts
  let trustedPubKey: JWK | undefined; // its public JWK, to check a rotation signature
  // The recovery policy in force, taken from the last entry we accepted. A
  // recovery is judged against what the identity had ALREADY committed to before
  // it happened, never against the policy the recovering entry declares for
  // itself, which an attacker would otherwise just write in their own favor.
  let trustedRecovery: RecoveryPolicy | undefined;
  let genesisKeyId: string | undefined;
  let prevHash: string | null = null;
  // Where this history begins. Normally 0. Higher means earlier entries were not
  // supplied, so the chain is judged from its own first entry onward and reported
  // as incomplete rather than as broken.
  let startsAt = 0;
  for (let i = 0; i < entries.length; i++) {
    const res = await verifySignedManifest(entries[i]);
    if (!res.valid || !res.manifest) {
      return { valid: false, complete: false, reason: `Entry ${i}: ${res.reason ?? 'signature did not verify'}`, length: entries.length };
    }
    const m = res.manifest;
    const seq = m.seq ?? 0;
    const prev = m.prev ?? null;
    if (i === 0) {
      if (seq < 0) return { valid: false, complete: false, reason: 'Entry 0: seq is negative.', length: entries.length };
      startsAt = seq;
      // A genesis, and only a genesis, has nothing before it. Where the history
      // is truncated, entry 0's prev points at an entry we were not given, so
      // there is nothing to check it against and we must not pretend otherwise.
      if (startsAt === 0 && prev !== null) {
        return { valid: false, complete: false, reason: 'Entry 0: a genesis entry must have no prev.', length: entries.length };
      }
    } else {
      if (seq !== startsAt + i) {
        return { valid: false, complete: false, startsAt, reason: `Entry ${i}: seq is ${seq}, expected ${startsAt + i}.`, length: entries.length };
      }
      if (prev !== prevHash) {
        return { valid: false, complete: false, startsAt, reason: `Entry ${i}: prev does not match the previous entry.`, length: entries.length };
      }
    }

    const entryKeyId = res.keyId!;
    if (trustedKeyId === undefined) {
      trustedKeyId = entryKeyId;
      genesisKeyId = entryKeyId;
      trustedPubKey = m.subject.publicKey;
    } else if (entryKeyId !== trustedKeyId) {
      // The key changed. Allowed only if the previous key authorized it, or if
      // enough keys the identity designated in advance did.
      const rot = m.rotation;
      if (!rot) return { valid: false, complete: false, startsAt, reason: `Entry ${i}: key changed without a rotation.`, length: entries.length };

      if (rot.prevKeySig) {
        if (rot.prevKeyId !== trustedKeyId) return { valid: false, complete: false, startsAt, reason: `Entry ${i}: rotation.prevKeyId is not the chain's current key.`, length: entries.length };
        try {
          const oldKey = await importJWK(trustedPubKey!, SIGNING_ALG);
          const { payload } = await compactVerify(rot.prevKeySig, oldKey);
          if (new TextDecoder().decode(payload) !== rotationStatement(entryKeyId, seq, prev)) {
            return { valid: false, complete: false, startsAt, reason: `Entry ${i}: rotation attestation does not match this entry.`, length: entries.length };
          }
        } catch {
          return { valid: false, complete: false, startsAt, reason: `Entry ${i}: rotation not signed by the previous key.`, length: entries.length };
        }
      } else if (rot.recovery?.length) {
        if (!isValidRecoveryPolicy(trustedRecovery)) {
          return { valid: false, complete: false, startsAt, reason: `Entry ${i}: recovery attempted but the identity had designated no recovery keys.`, length: entries.length };
        }
        const approvals = await countRecoveryApprovals(trustedRecovery, rot.recovery, entryKeyId, seq, prev);
        if (approvals < trustedRecovery.threshold) {
          return { valid: false, complete: false, startsAt, reason: `Entry ${i}: recovery has ${approvals} valid approval(s), needs ${trustedRecovery.threshold}.`, length: entries.length };
        }
      } else {
        return { valid: false, complete: false, startsAt, reason: `Entry ${i}: rotation carries no authorization.`, length: entries.length };
      }

      trustedKeyId = entryKeyId; // continuity: trust transfers to the new key
      trustedPubKey = m.subject.publicKey;
    } else {
      trustedPubKey = m.subject.publicKey;
    }
    // The policy this entry declares governs whatever comes after it.
    trustedRecovery = m.recovery;
    prevHash = await manifestJwsHash(entries[i].jws);
  }
  const complete = startsAt === 0;
  // A pinned key is a claim about the GENESIS, so an incomplete history can never
  // satisfy one: the entries that would connect this chain to the key you pinned
  // are exactly the ones missing. This is the security property that makes the
  // valid/complete split safe, so it must stay strict.
  if (expectedKeyId) {
    if (!complete) {
      return { valid: false, complete, startsAt, keyId: trustedKeyId, length: entries.length, reason: `This history starts at chain position ${startsAt}, so it cannot be checked against the key you pinned at the genesis.` };
    }
    if (genesisKeyId !== expectedKeyId) {
      return { valid: false, complete, startsAt, length: entries.length, reason: 'Chain does not start with the expected (pinned) key.' };
    }
  }
  return {
    valid: true,
    complete,
    startsAt,
    keyId: trustedKeyId,
    length: entries.length,
    ...(complete ? {} : { reason: `Every entry verified, but this history starts at chain position ${startsAt} rather than 0, so it cannot be traced back to the genesis.` }),
  };
}

/** Verify a signed pointer file (used for the "upload once" anchor). */
export async function verifyPointer(jws: string, expectedKeyId?: string): Promise<VerifyResult & { pointer?: PointerPayload }> {
  let peek: PointerPayload;
  try {
    const payloadB64 = jws.split('.')[1];
    if (!payloadB64) return { valid: false, reason: 'Malformed pointer JWS.' };
    peek = JSON.parse(new TextDecoder().decode(fromB64u(payloadB64))) as PointerPayload;
  } catch {
    return { valid: false, reason: 'Could not decode pointer.' };
  }
  const pubJwk = peek?.publicKey;
  if (peek?.type !== 'anchor-pointer' || !pubJwk || pubJwk.kty !== 'OKP' || pubJwk.crv !== 'Ed25519') {
    return { valid: false, reason: 'Not a valid RealHandles pointer file.' };
  }
  let bytes: Uint8Array;
  try {
    const key = await importJWK(pubJwk, SIGNING_ALG);
    bytes = (await compactVerify(jws, key)).payload;
  } catch {
    return { valid: false, reason: 'Pointer signature does not verify.' };
  }
  const pointer = JSON.parse(new TextDecoder().decode(bytes)) as PointerPayload;
  const computedKeyId = await keyIdFromJwk(pointer.publicKey);
  if (pointer.keyId !== computedKeyId) return { valid: false, reason: 'Pointer keyId does not match its key.' };
  if (expectedKeyId && expectedKeyId !== computedKeyId) return { valid: false, reason: 'Signed by a different key than the one you trust.', keyId: computedKeyId };
  return { valid: true, pointer, keyId: computedKeyId };
}

function fromB64u(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- trust score (post-MVP placeholder) ------------------------------------
// Intentionally not computed in the MVP. Documented here so the shape is fixed:
// score = f(quantity of verified real accounts, total reach/following). Left
// out until the core loop is solid, per scope.
