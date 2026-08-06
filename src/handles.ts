// Handle reservation + anti-squatting logic.
//
// The problem: short handles (realhandles.com/dvk) are valuable and must not be
// nabbed by whoever clicks first. The rule: the shorter the handle, the stronger
// the matching proof you must hold to claim it. A "match" is a verified account
// whose handle equals the username, or a domain you control whose label equals
// the username. Domains rank above platforms, and .com ranks above other TLDs.
//
// This module is dependency-free and isomorphic: the server enforces it and the
// dashboard uses it for a live preview. Keep it that way.

export type ProofKind = 'platform' | 'domain';

export interface Proof {
  kind: ProofKind;
  platform?: string; // when kind === 'platform'
  handle?: string; // the username on that platform
  domain?: string; // when kind === 'domain', e.g. "dvk.com"
  method: string; // 'oauth' | 'domain-control' | 'proof-post' | ...
  profileUrl?: string;
  verifiedAt: string;
  hidden?: boolean; // kept out of the public manifest when true
  metadata?: Record<string, unknown>;
}

type HandleShape = Pick<Proof, 'kind' | 'platform' | 'handle' | 'domain' | 'metadata'>;

// The handle a proof carries in the SIGNED manifest. A wallet with an ENS name
// publishes the .eth name, not the raw address, so the signer and any
// change-detection MUST resolve it the same way (a mismatch here was what made a
// wallet with an ENS show "unpublished changes" forever). Pure and isomorphic so
// it is unit-testable and shared by the dashboard signer and change-detector.
export function publishedHandle(p: HandleShape): string {
  if (p.kind === 'domain') return p.domain ?? '';
  const ens = typeof p.metadata?.ens === 'string' ? (p.metadata.ens as string) : undefined;
  // Same idea as ENS: publish the name a person actually uses, while the key
  // underneath stays the identity. A confirmed NIP-05 reads as
  // "davidvkimball.com" where an npub is 63 characters nobody can check by eye.
  const nip05 = typeof p.metadata?.nip05 === 'string' ? (p.metadata.nip05 as string) : undefined;
  return nip05 ?? ens ?? p.handle ?? '';
}

// A stable key for comparing what a proof would publish, using publishedHandle so
// change-detection matches exactly what the signer writes.
export function manifestKey(p: HandleShape): string {
  return p.kind === 'domain'
    ? `domain:${publishedHandle(p).toLowerCase()}`
    : `${p.platform}:${publishedHandle(p).toLowerCase()}`;
}

// Recognized key platforms. tier drives claim strength; `live` marks which ones
// we can verify today. Adding a platform is a one-line change here.
export const KEY_PLATFORMS: Record<string, { label: string; tier: 1 | 2; oauth: boolean; live: boolean }> = {
  x: { label: 'X', tier: 1, oauth: false, live: true }, // verified free via tweet + oEmbed
  bluesky: { label: 'Bluesky', tier: 1, oauth: false, live: true }, // via public atproto API
  youtube: { label: 'YouTube', tier: 1, oauth: false, live: true }, // via proof-post
  instagram: { label: 'Instagram', tier: 1, oauth: false, live: true },
  tiktok: { label: 'TikTok', tier: 1, oauth: false, live: true },
  linkedin: { label: 'LinkedIn', tier: 1, oauth: false, live: true },
  github: { label: 'GitHub', tier: 2, oauth: true, live: true },
  discord: { label: 'Discord', tier: 2, oauth: true, live: true },
  twitch: { label: 'Twitch', tier: 2, oauth: true, live: true },
  reddit: { label: 'Reddit', tier: 2, oauth: false, live: false }, // disabled: Reddit blocks unauthenticated reads; waiting on API access
  dribbble: { label: 'Dribbble', tier: 2, oauth: true, live: true },
  gitlab: { label: 'GitLab', tier: 2, oauth: true, live: true },
};

// TLD ranking. .com is deliberately on top, per the design.
const TLD_SCORE: Record<string, number> = { com: 100 };
const STRONG_TLDS = new Set(['net', 'org', 'io', 'co', 'app', 'dev', 'me', 'xyz']);

// System routes and words that can never be claimed by anyone.
export const RESERVED_WORDS = new Set([
  'api', 'app', 'verify', 'admin', 'about', 'login', 'logout', 'schema', 'well-known',
  'assets', '_astro', 'static', 'favicon', 'robots', 'sitemap', 'realhandles', 'u',
  'support', 'help', 'root', 'www', 'mail', 'official', 'staff', 'mod', 'moderator',
  'team', 'security', 'abuse', 'legal', 'privacy', 'terms', 'status', 'docs', 'blog',
  // Current page slugs (a static page shadows a [username] match, so these must
  // never be claimable) plus a curated set reserved for likely future pages, so
  // we can ship them without bumping anyone off an already-claimed handle.
  'directory', 'spec', 'compare', 'report', 'settings', 'account', 'dashboard',
  'contact', 'pricing', 'faq', 'explore', 'search', 'discover', 'profile', 'me',
  'home', 'new', 'edit', 'onboarding', 'welcome',
  // Impersonation and phishing bait. These are roles and prompts, not names: a
  // handle like @walletrecovery or @realhandlessupport is only ever useful for
  // convincing someone to hand over money or a key. No proof unlocks them,
  // because no proof makes them safe to hand out. That is why they live here
  // and not in PROTECTED_NAMES below.
  '2fa', 'accounts', 'administrator', 'administrators', 'airdrop', 'airdrops', 'alert',
  'alerts', 'amazonaws', 'auth', 'authentication', 'banking', 'billing', 'checkout',
  'credentials', 'cryptosupport', 'customercare', 'customerservice', 'customersupport',
  'do-not-reply', 'donotreply', 'emergency', 'emergencyservices', 'escrow', 'firedepartment',
  'giveaway', 'giveaways', 'government', 'helpcenter', 'helpdesk', 'helpline', 'hostmaster',
  'invoice', 'invoices', 'mailer-daemon', 'mfa', 'moderation', 'moderators', 'no-reply',
  'noreply', 'notification', 'notifications', 'oauth', 'office365', 'otp', 'passcode',
  'password', 'passwords', 'payment', 'payments', 'payout', 'payouts', 'policedepartment',
  'postmaster', 'privatekey', 'publichealth', 'realhandleshelp', 'realhandlesofficial',
  'realhandlessupport', 'realhandlesteam', 'recovery', 'recoveryphrase', 'refund', 'refunds',
  'seedphrase', 'servicedesk', 'signin', 'signup', 'supportteam', 'sysadmin', 'techsupport',
  'transaction', 'transactions', 'trustandsafety', 'verification', 'verified', 'wallet',
  'walletrecovery', 'walletsupport', 'webmaster',
]);

// Names that are protected by WHAT THEY ARE, not by how long they are.
//
// The length rule protects scarcity: the shorter a handle, the stronger the
// proof needed. It says nothing about a long name that is nonetheless famous.
// "microsoft" is 9 characters and "cloudflare" is 10, so both fell into the
// open tier and could be taken by anyone with a keyboard. This list closes that
// hole by raising such a name to the Protected tier at any length.
//
// It is not a block list. Microsoft still gets @microsoft, by proving
// @microsoft on a key platform or control of microsoft.com, through exactly the
// same gate everyone else goes through. Nobody else gets it.
//
// Deliberately NOT here:
// - Common first names. "jack" is 4 characters, so the length rule already
//   makes it Protected and already demands a matching verified proof. A names
//   list would add nothing and would punish people for being called Jack.
// - Impersonation and phishing terms (support, billing, seedphrase). Those are
//   in RESERVED_WORDS above, because no proof should unlock them.
// - Handles we operate or route ourselves. Those are RESERVED_WORDS too.
//
// Entries are lowercase, deduplicated, sorted, and matched exactly: this gate
// keys on the whole handle, so "microsoft" is covered and "microsoftfan" is not.
export const PROTECTED_NAMES = new Set([
  '1password', 'abercrombie', 'absolutvodka', 'accenture', 'activision', 'aeromexico',
  'aircanada', 'airfrance', 'alaskaair', 'alfaromeo', 'aliexpress', 'aljazeera', 'americanair',
  'americanairlines', 'americanexpress', 'anthropic', 'applebees', 'astonmartin', 'atlassian',
  'automattic', 'balenciaga', 'bankofamerica', 'barclaycard', 'baskinrobbins', 'benandjerrys',
  'bigcommerce', 'birkenstock', 'bitbucket', 'bitwarden', 'blackrock', 'bloomberg',
  'bloomingdales', 'bnpparibas', 'bookingcom', 'bridgestone', 'britishairways', 'budweiser',
  'burgerking', 'bytedance', 'calvinklein', 'capitalone', 'carlsberg', 'carrefour',
  'cartoonnetwork', 'cathaypacific', 'charlesschwab', 'chasebank', 'chevrolet',
  'chickfila', 'citigroup', 'clevelandclinic', 'cloudflare', 'coastguard', 'coingecko',
  'coinmarketcap', 'creditkarma', 'crimestoppers', 'crowdstrike', 'crunchyroll',
  'curvefinance', 'dartmouth', 'databricks', 'deliveroo', 'deutschebank', 'dickssportinggoods',
  'digitalocean', 'discovercard', 'disneyplus', 'dolcegabbana', 'dollargeneral', 'doubletree',
  'downingstreet', 'dreamworks', 'duckduckgo', 'dunkindonuts', 'eigenlayer', 'elasticsearch',
  'electrolux', 'elevenlabs', 'epicgames', 'esteelauder', 'etherscan',
  'etihadairways', 'europeancommission', 'europeanunion', 'expressvpn', 'familydollar',
  'fcbarcelona', 'federalreserve', 'ferrerorocher', 'financialtimes', 'fisherprice',
  'footlocker', 'forever21', 'fourseasons', 'generalmills', 'goldmansachs', 'googlecloud',
  'greenpeace', 'haagendazs', 'harleydavidson', 'hashicorp', 'healthcanada', 'hellofresh',
  'holidayinn', 'hollywoodreporter', 'homedepot', 'homelandsecurity', 'huggingface',
  'indiegogo', 'instacart', 'instagram', 'interactivebrokers', 'intercontinental',
  'internetarchive', 'jackdaniels', 'jetbrains', 'johnniewalker', 'johnshopkins',
  'jpmorganchase', 'kaspersky', 'katespade', 'kickstarter', 'kitchenaid', 'kraftheinz',
  'krispykreme', 'kubernetes', 'lamborghini', 'landrover', 'letsencrypt', 'letterboxd',
  'lidofinance', 'linuxfoundation', 'lionsgate', 'listerine', 'livenation', 'liverpoolfc',
  'lloydsbank', 'lonelyplanet', 'lorealparis', 'louisvuitton', 'lufthansa', 'lululemon',
  'magiceden', 'mailchimp', 'manchesterunited', 'marksandspencer', 'mastercard', 'maybelline',
  'mayoclinic', 'mcdonalds', 'mercadolibre', 'mercadopago', 'mercedesbenz', 'metatrader',
  'michaelkors', 'microsoft', 'midjourney', 'minecraft', 'mistralai', 'mitsubishi', 'moneygram',
  'morganstanley', 'namecheap', 'nationalgeographic', 'nationalguard', 'navyfederal',
  'nespresso', 'neutrogena', 'newbalance', 'nhsengland', 'nickelodeon', 'nordstrom',
  'notredame', 'olivegarden', 'panasonic', 'pancakeswap', 'panerabread', 'paramountplus',
  'patekphilippe', 'pillsbury', 'pinterest', 'playmobil', 'playstation',
  'polymarket', 'postalservice', 'postgresql', 'premierleague', 'priceline', 'primevideo',
  'princeton', 'producthunt', 'protonmail', 'qatarairways', 'quickbooks', 'rackspace',
  'ralphlauren', 'raspberrypi', 'realmadrid', 'redcrescent', 'riotgames', 'ritzcarlton',
  'robinhood', 'rocketmortgage', 'rockstargames', 'rollingstone', 'rollsroyce',
  'rottentomatoes', 'sainsburys', 'salesforce', 'salvationarmy', 'samsonite', 'sanpellegrino',
  'santander', 'savethechildren', 'scotiabank', 'sendgrid', 'sentinelone', 'servicenow',
  'sharepoint', 'signalapp', 'singaporeair', 'socialsecurity', 'soundcloud', 'sourceforge',
  'southwestair', 'squarespace', 'stabilityai', 'stackexchange', 'stackoverflow',
  'standardchartered', 'starbucks', 'statedepartment', 'stellaartois', 'sushiswap', 'swarovski',
  'teamviewer', 'techcrunch', 'telemundo', 'terraform', 'theeconomist', 'theguardian',
  'thenorthface', 'ticketmaster', 'tiffanyandco', 'timberland', 'toblerone', 'tommyhilfiger',
  'traderjoes', 'tradingview', 'transunion', 'tripadvisor', 'tropicana', 'trustwallet',
  'tupperware', 'turkishairlines', 'ukgovernment', 'underarmour', 'unitedairlines',
  'unitednations', 'univision', 'urbanoutfitters', 'usembassy', 'usgovernment', 'vanityfair',
  'victoriassecret', 'virginatlantic', 'visualstudio', 'volkswagen', 'walgreens',
  'walletconnect', 'warnerbros', 'washingtonpost', 'wealthfront', 'wellsfargo', 'westernunion',
  'westpoint', 'whitehouse', 'wholefoods', 'wikimedia', 'wikipedia', 'woocommerce',
  'woolworths', 'wordpress', 'worldbank', 'ycombinator',
]);

// Operator-curated aliases: a reserved handle that points to a canonical
// identity's username. This lets the operator hand a scarce or vanity handle
// (e.g. a founder's short name) to an existing identity that the automatic gate
// would not grant, because the gate keys on an exact handle match. An alias can
// NEVER be claimed by anyone (it is treated as reserved), and the public profile
// route 301-redirects /<alias> to /<target>. Keys and values are lowercase.
export const HANDLE_ALIASES: Record<string, string> = {
  david: 'davidvkimball',
};

/** The canonical username an alias points to, or null if the handle is not one. */
export function aliasTarget(username: string): string | null {
  const u = normalizeHandle(username);
  return Object.hasOwn(HANDLE_ALIASES, u) ? HANDLE_ALIASES[u] : null;
}

export function normalizeHandle(s: string): string {
  // Strip a leading @ (and any spaces) so users can type "@name" or "name".
  return s.trim().replace(/^@+/, '').toLowerCase();
}

// Pretty display names for platforms whose icon key does not capitalize nicely
// (multi-word or specific casing). Keyed by the same key iconKey() resolves to.
const PLATFORM_LABELS: Record<string, string> = {
  stackoverflow: 'Stack Overflow', stackexchange: 'Stack Exchange', hackernews: 'Hacker News',
  ycombinator: 'Y Combinator', googlescholar: 'Google Scholar', googleplay: 'Google Play',
  appstore: 'App Store', lastfm: 'Last.fm', deviantart: 'DeviantArt', artstation: 'ArtStation',
  soundcloud: 'SoundCloud', researchgate: 'ResearchGate', producthunt: 'Product Hunt',
  raspberrypi: 'Raspberry Pi', wordpress: 'WordPress', devto: 'DEV', dev: 'DEV',
  angellist: 'AngelList', vk: 'VK', qq: 'QQ', imdb: 'IMDb', npm: 'npm', tiktok: 'TikTok',
  wechat: 'WeChat', paypal: 'PayPal', ebay: 'eBay', codepen: 'CodePen', node: 'Node.js',
  gitlab: 'GitLab', bitbucket: 'Bitbucket', letterboxd: 'Letterboxd', orcid: 'ORCID',
  hackerrank: 'HackerRank', slideshare: 'SlideShare', xing: 'XING', discourse: 'Discourse',
  flipboard: 'Flipboard', audible: 'Audible', quora: 'Quora', scribd: 'Scribd',
  ethereum: 'Ethereum', bitcoin: 'Bitcoin', ens: 'ENS',
};

/** Display label for a platform, e.g. "x" -> "X", "github" -> "GitHub". */
export function platformLabel(platform: string): string {
  const p = platform.toLowerCase();
  return KEY_PLATFORMS[p]?.label ?? PLATFORM_LABELS[p] ?? p.charAt(0).toUpperCase() + p.slice(1);
}

// A recognized link-in-bio builder's display name, or null for an unknown one.
// Keep the keys in sync with KNOWN_BUILDERS in api/proof-post/verify.ts.
export function builderLabel(builder: string | null | undefined): string | null {
  if (!builder) return null;
  return builder.toLowerCase() === 'lilhub' ? 'lilHub' : null;
}

// A clean, readable page URL for a link-in-bio row: host + path, no protocol or
// trailing slash (e.g. "linktr.ee/you", "yoursite.com").
export function prettyPageUrl(u: string): string {
  try {
    const x = new URL(u);
    return (x.hostname.replace(/^www\./, '') + x.pathname).replace(/\/+$/, '') || x.hostname;
  } catch {
    return u;
  }
}

export function cleanDomain(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '');
}

export function domainLabel(domain: string): string {
  return cleanDomain(domain).split('.')[0] ?? '';
}

export function domainTld(domain: string): string {
  const parts = cleanDomain(domain).split('.');
  return parts.length > 1 ? parts.slice(1).join('.') : '';
}

// Methods where a first party confirms WHO controls the account: OAuth, an
// author-bound post (X/TikTok oEmbed), a platform API lookup (YouTube/Bluesky),
// a DNS / well-known record (domain), or a MUTUAL rel="me" link (the person
// listed the page AND the page links back to this exact profile, the IndieWeb
// two-way binding). These show as "Verified". A verified rel="me" still cannot
// gate a PROTECTED short handle unless the platform is a curated key platform
// (see proofStrength), so a self-made link-in-bio can never grab a scarce name.
// Everything else - a lone bio token, a best-effort page fetch (Instagram/
// LinkedIn), or a bare self-assertion - shows as "Claimed".
export const VERIFIED_METHODS = new Set([
  'oauth', 'tweet-proof', 'post-proof', 'description-proof', 'atproto',
  'domain-control', 'domain-anchor', 'wallet-signature', 'rel-me',
  // A Nostr account IS a keypair, so a signature over our challenge proves
  // control directly. No platform is asked and no page is read, which puts it
  // alongside the wallet and domain proofs rather than the bio-reading ones.
  'nostr-signature',
]);

/** True when a first party confirmed the account (vs. a claim / URL-control proof). */
export function isVerifiedMethod(method: string): boolean {
  return VERIFIED_METHODS.has(method);
}

/** Strength of one proof for a given desired username. 0 means it does not match. */
export function proofStrength(username: string, p: Proof): number {
  // Only first-party-verified proofs gate a protected handle. Claims and
  // URL-control proofs never do. rel="me" is Verified for display and the trust
  // score, but a URL-control proof is too easy to mint a namesake on, so it
  // never reserves a scarce handle (even on a key platform).
  if (!isVerifiedMethod(p.method) || p.method === 'rel-me') return 0;
  const u = normalizeHandle(username);
  if (p.kind === 'domain' && p.domain) {
    if (domainLabel(p.domain) !== u) return 0;
    const tld = domainTld(p.domain);
    // .com is top; a curated set of established TLDs is strong; everything else
    // scores below the gating threshold so a throwaway/cheap TLD (buy ben.xyz for
    // a dollar) cannot clear a scarce name. It still adds to the trust score.
    return TLD_SCORE[tld] ?? (STRONG_TLDS.has(tld) ? 80 : 30);
  }
  if (p.kind === 'platform' && p.platform && p.handle) {
    if (normalizeHandle(p.handle) !== u) return 0;
    const meta = KEY_PLATFORMS[p.platform.toLowerCase()];
    // Only curated key platforms (and domains) can gate a PROTECTED short handle.
    // An unlisted platform is verified generically (bio-token / rel="me"), which
    // proves control of that URL but is too easy to mint a namesake on to justify
    // reserving a scarce handle. It still counts for the public trust score.
    if (!meta) return 0;
    return meta.tier === 1 ? 60 : 40;
  }
  return 0;
}

// --- trust score -----------------------------------------------------------
// "Quantity as credibility": more verified real accounts + a controlled domain
// = a more trustworthy identity, which in turn is what makes a self-attested
// ("claimed") account believable. Reach (follower counts) is not yet fetched, so
// this is a quantity/quality score for now; reach can be folded in later when we
// pull follower numbers from the platform APIs.
export interface TrustScore {
  score: number; // 0-100
  verifiedCount: number;
  domains: number;
  // Per-proof contributions, so the score is an argument rather than a mystery
  // number. Sums to `raw`, which is capped at 100 for `score`.
  parts: { label: string; points: number }[];
  raw: number;
}

export function computeTrustScore(proofs: Proof[]): TrustScore {
  let raw = 0;
  let verifiedCount = 0;
  let domains = 0;
  const parts: { label: string; points: number }[] = [];
  for (const p of proofs) {
    if (!isVerifiedMethod(p.method)) continue; // only first-party-verified accounts add trust
    if (p.kind === 'domain') {
      domains++;
      const points = domainTld(p.domain ?? '') === 'com' ? 25 : 15;
      raw += points;
      parts.push({ label: `${p.domain} (verified domain)`, points });
    } else if (p.kind === 'platform') {
      verifiedCount++;
      const tier = KEY_PLATFORMS[(p.platform ?? '').toLowerCase()]?.tier;
      const points = tier === 1 ? 15 : tier === 2 ? 9 : 5;
      raw += points;
      parts.push({ label: `${p.handle} on ${platformLabel(p.platform ?? '')}`, points });
    }
  }
  return { score: Math.min(100, raw), verifiedCount, domains, parts, raw };
}

export interface ClaimBasis {
  via: string; // 'x', 'github', 'domain', ...
  detail: string; // '@dvk on X', 'dvk.com', ...
  score: number;
}

export function bestClaim(username: string, proofs: Proof[]): ClaimBasis | null {
  let best: ClaimBasis | null = null;
  for (const p of proofs) {
    const score = proofStrength(username, p);
    if (score <= 0) continue;
    const basis: ClaimBasis =
      p.kind === 'domain'
        ? { via: 'domain', detail: cleanDomain(p.domain!), score }
        : { via: p.platform!, detail: `@${p.handle} on ${KEY_PLATFORMS[p.platform!.toLowerCase()]?.label ?? p.platform}`, score };
    if (!best || basis.score > best.score) best = basis;
  }
  return best;
}

export interface Tier {
  name: 'reserved' | 'premium' | 'open';
  minScore: number;
  label: string;
  note: string;
  // True when the tier came from the name being well known rather than short.
  // Callers use it to explain the refusal honestly: "Open (9+ characters)" is a
  // lie for @microsoft, and a person refused a handle deserves the real reason.
  protectedName?: boolean;
}

// Strictness order, so two tiers can be compared and the stronger one wins.
const TIER_RANK: Record<Tier['name'], number> = { open: 0, premium: 1, reserved: 2 };

/** Length-based protection tier. Thresholds live here so they are easy to tune. */
function tierForLength(username: string): Tier {
  const len = normalizeHandle(username).length;
  if (len <= 2) {
    return {
      name: 'reserved',
      minScore: 60,
      label: 'Reserved (1-2 characters)',
      note: 'Very short handles need a matching .com you control, or a matching handle on a tier-1 platform (X, YouTube, TikTok, Instagram, LinkedIn).',
    };
  }
  if (len <= 8) {
    return {
      name: 'premium',
      minScore: 40,
      label: 'Protected (3-8 characters)',
      note: 'Handles of 8 characters or fewer need at least one matching verified account (on a key platform) or a domain you control before you can claim them.',
    };
  }
  return {
    name: 'open',
    minScore: 0,
    label: 'Open (9+ characters)',
    note: 'This handle is open to claim. A matching verified account or domain adds a namesake badge.',
  };
}

/**
 * Protection tier for a handle, from its length AND its name.
 *
 * Length alone left a hole: "microsoft" is 9 characters, so the open tier handed
 * it to whoever typed fastest. A name in PROTECTED_NAMES is Protected at any
 * length, and the stronger of the two tiers wins, so a well-known two-letter
 * name stays Reserved rather than dropping to Protected. The gate itself is
 * unchanged: it is still the same proof match, just at a higher bar.
 */
export function tierFor(username: string): Tier {
  const u = normalizeHandle(username);
  const byLength = tierForLength(u);
  if (!PROTECTED_NAMES.has(u)) return byLength;
  const byName: Tier = {
    name: 'premium',
    minScore: 40,
    label: 'Protected (well-known name)',
    note: `@${u} is a widely recognized name, so it is protected whatever its length. Verify a matching account on a key platform, or prove you control ${u}.com, and it is yours.`,
    protectedName: true,
  };
  return TIER_RANK[byLength.name] > TIER_RANK[byName.name] ? byLength : byName;
}

export interface ClaimEval {
  username: string;
  valid: boolean;
  reservedWord: boolean;
  tier: Tier;
  score: number;
  basis: ClaimBasis | null;
  qualifies: boolean;
  message: string;
  howToQualify: string[];
}

export function isValidFormat(username: string): boolean {
  return /^[a-z0-9][a-z0-9_-]{0,38}$/.test(normalizeHandle(username));
}

/** The single decision function used by the server gate and the live preview. */
export function evaluateClaim(username: string, proofs: Proof[]): ClaimEval {
  const u = normalizeHandle(username);
  const tier = tierFor(u);
  const basis = bestClaim(u, proofs);
  const score = basis?.score ?? 0;
  // Alias handles are reserved too: they already point to a canonical identity,
  // so no one else can claim them.
  const reservedWord = RESERVED_WORDS.has(u) || Object.hasOwn(HANDLE_ALIASES, u);
  const valid = isValidFormat(u) && !reservedWord && u.length >= 1;
  const qualifies = valid && score >= tier.minScore;

  let message: string;
  if (reservedWord) message = 'That handle is reserved by the system and cannot be claimed.';
  else if (!isValidFormat(u)) message = 'Handles are 1-39 characters: letters, numbers, hyphen, underscore, starting with a letter or number.';
  else if (qualifies) {
    if (tier.name === 'open') {
      message = basis
        ? `Open handle, and you have a namesake match via ${basis.detail}.`
        : 'This handle is open to claim.';
    } else if (tier.protectedName) {
      message = `@${u} is a protected name, and you qualify via ${basis!.detail}.`;
    } else {
      message = `You qualify for this ${tier.name} handle via ${basis!.detail}.`;
    }
  } else {
    // A name-protected tier already explains itself, including why this handle
    // is gated and what unlocks it, so do not bury it behind "premium handle".
    message = tier.protectedName ? tier.note : `This is a ${tier.name} handle. ${tier.note}`;
  }

  // The advice has to name routes that actually clear THIS tier's minScore.
  // It used to list GitHub for every tier, including the 1-2 character one where
  // minScore is 60 and GitHub scores 40, so it told people to go and do
  // something that could not work. Tier 2 platforms are named only when 40 is
  // enough, and Bluesky was missing from the tier 1 list entirely.
  const howToQualify: string[] = [];
  if (!qualifies && !reservedWord && isValidFormat(u)) {
    const tier1 = Object.entries(KEY_PLATFORMS)
      .filter(([, meta]) => meta.tier === 1)
      .map(([, meta]) => meta.label);
    const tier2 = Object.entries(KEY_PLATFORMS)
      .filter(([, meta]) => meta.tier === 2)
      .map(([, meta]) => meta.label);
    const usable = tier.minScore <= 40 ? [...tier1, ...tier2] : tier1;
    howToQualify.push(`Verify @${u} on a key platform (${usable.join(', ')}).`);
    howToQualify.push(
      tier.minScore <= 40
        ? `Prove you control ${u}.com (or another established TLD) via the domain challenge.`
        : `Prove you control ${u}.com via the domain challenge. A cheaper TLD does not reach this tier.`,
    );
  }

  return { username: u, valid, reservedWord, tier, score, basis, qualifies, message, howToQualify };
}
