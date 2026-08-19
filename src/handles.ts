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
  'directory', 'spec', 'compare', 'report', 'build', 'settings', 'account', 'dashboard',
  'contact', 'pricing', 'faq', 'explore', 'search', 'discover', 'profile', 'me',
  'home', 'new', 'edit', 'onboarding', 'welcome',
  // Privileged-sounding roles. A handle only has to LOOK like staff to work as
  // bait, so these are refused outright rather than gated behind a proof: no
  // proof makes @sudo or @operator safe to hand to a stranger.
  'su', 'sudo', 'system', 'operator', 'owner', 'internal',
  // Placeholder values that a bug can produce as if they were a real name.
  // Someone reaching @null because a field was empty must not find a person
  // there, and "undefined" as a claimable handle is an invitation to farm
  // whatever misroutes into it.
  'null', 'undefined', 'none', 'true', 'false', 'nobody', 'anonymous', 'anon',
  'guest', 'user', 'users',
  // Scaffolding names. Cheap to reserve, and awkward to reclaim later from
  // somebody who got there first.
  'test', 'demo', 'example', 'sample', 'dev', 'staging', 'prod', 'production',
  'alpha', 'beta', 'debug', 'console', 'config', 'script',
  // More likely future pages, reserved now so shipping one never bumps anyone
  // off a handle they already hold.
  'about-us', 'careers', 'jobs', 'press', 'media', 'brand', 'trust', 'safety',
  'changelog', 'roadmap', 'download', 'downloads', 'install', 'signup', 'signin',
  'register', 'invite', 'invites', 'extension', 'notifications', 'messages',
  'inbox', 'feed', 'trending', 'popular', 'top', 'all', 'public',
  // Protocol nouns. A handle named after the mechanism reads as the mechanism
  // speaking, which is exactly the confusion a phisher wants.
  'vouch', 'vouches', 'key', 'keys', 'rotate', 'rotation', 'recovery', 'recover',
  'claim', 'claims', 'anchor', 'manifest', 'proof', 'proofs',
  // The word for the thing this site hands out. "@handle says your handle is
  // suspended" reads as the system, not as a person, and that is the entire
  // trick. Same reason 'realhandles' is here: the product's own nouns must not
  // be wearable. 'username' is the same word in the other register, reserved so
  // the obvious substitution does not walk straight through.
  'handle', 'handles', 'realhandle', 'username', 'usernames', 'name', 'names',
  'identity', 'identities',
  // The rest of the mechanism, which the list above had started on and left
  // half done. Each of these already names something the product does, so a
  // person holding one is a person who can be mistaken for the thing itself.
  'did', 'dids', 'didkey', 'chain', 'sigchain', 'disavow', 'disavowal',
  'disavowals', 'sign', 'signed', 'signature', 'signatures', 'attest',
  'attestation', 'attestations', 'timestamp', 'timestamps', 'pin', 'pins',
  'pinned', 'badge', 'badges', 'trusted',
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
  'noreply', 'notification', 'oauth', 'office365', 'otp', 'passcode',
  'password', 'passwords', 'payment', 'payments', 'payout', 'payouts', 'policedepartment',
  'postmaster', 'privatekey', 'publichealth', 'realhandleshelp', 'realhandlesofficial',
  'realhandlessupport', 'realhandlesteam', 'recoveryphrase', 'refund', 'refunds',
  'seedphrase', 'servicedesk', 'supportteam', 'sysadmin', 'techsupport',
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

// --- reserved handles that a specific, provable claim can unlock -------------
//
// RESERVED_WORDS is a hard block, and for almost everything in it that is the
// right answer: no proof makes @admin or @seedphrase safe to hand to a stranger,
// because the danger is what the name SAYS, not who holds it.
//
// A few entries are different. @realhandles is dangerous in exactly one
// direction, which is somebody who is not us holding it. There is a party for
// whom it is not dangerous at all, and they can prove who they are. For that
// case a flat refusal is the wrong shape twice over: it tells a legitimate
// claimant nothing about whether they can ever have the name, and it makes the
// answer an email to the operator rather than a rule anybody can read.
//
// **How this differs from PROTECTED_NAMES, which is a mechanism that already
// exists.** PROTECTED_NAMES raises a name's TIER, so @microsoft is scored
// through the ordinary gate at a higher bar and any single matching key-platform
// handle or matching .com clears it. It is a difficulty setting on a gate
// everybody walks through. This is not that. An unlock names the SPECIFIC proofs
// for one specific handle, requires ALL of them, and the handle stays refused to
// everyone else no matter how strong an unrelated proof they hold. Put a brand
// in PROTECTED_NAMES when the ordinary rules should apply more strictly; put one
// here only when a name is otherwise unclaimable and exactly one party should be
// able to open it.
//
// Reserved-ness stays the DEFAULT. An entry in RESERVED_WORDS is unlockable only
// if it is also named here.

export type ReservedRequirement =
  | { kind: 'domain'; domain: string }
  | { kind: 'platform'; platform: string; handle: string };

/** A reserved handle that a specific, provable claim can unlock. */
export interface ReservedUnlock {
  handle: string;
  /**
   * ALL of these must be satisfied. Deliberately AND, not OR.
   *
   * These are the most impersonation-sensitive names in the system, so the bar
   * is higher than for an ordinary short handle, where one matching proof is
   * enough. Two independent proofs also means losing one of them (a lapsed
   * domain, a transferred org) does not by itself hand the name to whoever
   * picked it up.
   */
  requires: ReservedRequirement[];
  why: string;
}

export const RESERVED_UNLOCKS: ReservedUnlock[] = [
  {
    handle: 'realhandles',
    requires: [
      { kind: 'domain', domain: 'realhandles.com' },
      { kind: 'platform', platform: 'github', handle: 'realhandles' },
    ],
    why: 'This is the name of the service itself, so it is the single most useful handle an impersonator could hold.',
  },
];

/** The unlock rule for a handle, or null when nothing can open it. */
export function reservedUnlockFor(username: string): ReservedUnlock | null {
  const u = normalizeHandle(username);
  return RESERVED_UNLOCKS.find((r) => r.handle === u) ?? null;
}

/** Does this proof satisfy this requirement? Verified proofs only, exact match only. */
function satisfies(req: ReservedRequirement, p: Proof): boolean {
  // The same bar the scarce-name gate uses. A claimed account must never open a
  // reserved handle, and neither may a rel="me" link, which is only URL control
  // and is the cheapest thing on this list for an impersonator to arrange.
  if (!isNameGatingMethod(p.method)) return false;
  if (req.kind === 'domain') {
    return p.kind === 'domain' && !!p.domain && cleanDomain(p.domain) === cleanDomain(req.domain);
  }
  return (
    p.kind === 'platform' &&
    !!p.platform &&
    !!p.handle &&
    p.platform.toLowerCase() === req.platform.toLowerCase() &&
    normalizeHandle(p.handle) === normalizeHandle(req.handle)
  );
}

/** How a requirement reads to a person who has to go and satisfy it. */
export function describeRequirement(req: ReservedRequirement): string {
  return req.kind === 'domain'
    ? `control of ${cleanDomain(req.domain)}`
    : `@${normalizeHandle(req.handle)} on ${platformLabel(req.platform)}`;
}

export interface UnlockStatus {
  unlock: ReservedUnlock;
  met: ReservedRequirement[];
  missing: ReservedRequirement[];
  unlocked: boolean;
}

/**
 * Which of a reserved handle's requirements these proofs already satisfy.
 *
 * Returns the breakdown rather than a boolean so the refusal can say which ones
 * are done and which are left. A gate that refuses without saying why is
 * indistinguishable from a bug, and the person on the other side of this one is
 * by definition somebody who probably can satisfy it.
 */
export function unlockStatus(unlock: ReservedUnlock, proofs: Proof[]): UnlockStatus {
  const met: ReservedRequirement[] = [];
  const missing: ReservedRequirement[] = [];
  for (const req of unlock.requires) {
    if (proofs.some((p) => satisfies(req, p))) met.push(req);
    else missing.push(req);
  }
  return { unlock, met, missing, unlocked: missing.length === 0 };
}

/**
 * True when NOTHING can claim this handle, including a perfect proof set.
 *
 * The public answer to "is this reserved", used wherever a caller has no proofs
 * to evaluate. Exported so the API route and evaluateClaim cannot disagree about
 * it, which they previously could: the route checked RESERVED_WORDS alone and
 * missed aliases.
 */
export function isHardReserved(username: string): boolean {
  const u = normalizeHandle(username);
  if (Object.hasOwn(HANDLE_ALIASES, u)) return true;
  return RESERVED_WORDS.has(u) && !reservedUnlockFor(u);
}

export function normalizeHandle(s: string): string {
  // Strip a leading @ (and any spaces) so users can type "@name" or "name".
  //
  // SLASHES GO TOO, at both ends, and that rule is here because its absence
  // reached production: a claimed account rendered as "/davidvkimball on Build
  // in public" on 2026-08-19. Nothing addressable is called "/name". What
  // produces one is somebody pasting a URL path into a handle field, which is an
  // ordinary thing to do and was silently kept because the @ rule lived here and
  // this one did not.
  //
  // Only the ENDS are trimmed. A handle with an interior slash is a different
  // mistake, and rewriting "a/b" into "ab" would invent an account nobody typed.
  return s.trim().replace(/^[@/]+/, '').replace(/\/+$/, '').trim().toLowerCase();
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

/** Whether a stored profile URL is real enough to show as a link. */
export function linkableProfileUrl(profileUrl: string | undefined | null, platform?: string): string | null {
  const u = (profileUrl ?? '').trim();
  if (!u || !/^https?:\/\//i.test(u)) return null;
  if (platform) {
    const plat = platform.trim().toLowerCase();
    const bare = u.replace(/\/+$/, '').toLowerCase();
    if (bare === `https://${plat}` || bare === `http://${plat}`) return null;
  }
  return u;
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

/**
 * May this method decide who gets a NAME, as opposed to what shows on a profile?
 *
 * Stricter than isVerifiedMethod on purpose, and by exactly one method. rel="me"
 * is Verified for display and for the trust score, because a mutual link really
 * does prove control of that page. It is still only URL control, and a namesake
 * page is cheap to mint, so it must never be what wins a scarce or reserved
 * name from somebody.
 *
 * Shared by proofStrength and the reserved-handle unlock below so the two cannot
 * drift apart. They had no reason to disagree, and a gate that quietly relaxed
 * on one path and not the other is the kind of difference nobody notices until
 * it is being exploited.
 */
export function isNameGatingMethod(method: string): boolean {
  return isVerifiedMethod(method) && method !== 'rel-me';
}

/** Strength of one proof for a given desired username. 0 means it does not match. */
export function proofStrength(username: string, p: Proof): number {
  // Only first-party-verified proofs gate a protected handle. Claims and
  // URL-control proofs never do. See isNameGatingMethod for why rel="me" is
  // Verified everywhere else and still excluded here.
  if (!isNameGatingMethod(p.method)) return 0;
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
  /**
   * Set only for a reserved handle that a named proof set can open, so a caller
   * can show progress rather than a wall. Absent for every ordinary handle and
   * for the ones nothing unlocks.
   */
  unlock?: UnlockStatus;
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
  // A reserved handle that names the proofs which open it is evaluated against
  // THESE proofs. Everything else in RESERVED_WORDS, and every alias, stays a
  // flat refusal: an alias already points at a canonical identity, and the rest
  // are dangerous because of what the name says rather than who holds it.
  const unlockRule = RESERVED_WORDS.has(u) ? reservedUnlockFor(u) : null;
  const unlock = unlockRule ? unlockStatus(unlockRule, proofs) : undefined;
  const reservedWord = isHardReserved(u) || (!!unlock && !unlock.unlocked);
  const valid = isValidFormat(u) && !reservedWord && u.length >= 1;
  // An unlock IS the gate for its handle. The tier gate exists for names that
  // are scarce by length or fame, and an unlock is strictly more specific and
  // strictly stronger, so clearing it is not then second-guessed by a score.
  const qualifies = valid && (unlock?.unlocked === true || score >= tier.minScore);

  let message: string;
  if (unlock && !unlock.unlocked) {
    // The refusal a person can act on. Naming what is still needed, and what is
    // already done, is the whole difference between a rule and an email to the
    // operator.
    const needed = unlock.unlock.requires.map(describeRequirement).join(' AND ');
    // Only credit progress once there is some. With nothing met, "still needed"
    // would just repeat the full list back, which reads like the gate is longer
    // than it is.
    const progress = unlock.met.length
      ? ` You have ${unlock.met.length} of ${unlock.unlock.requires.length}: ${unlock.met.map(describeRequirement).join(', ')}.` +
        ` Still needed: ${unlock.missing.map(describeRequirement).join(', ')}.`
      : '';
    message = `@${u} is reserved. ${unlock.unlock.why} It opens for exactly one claim: ${needed}.${progress}`;
  } else if (unlock?.unlocked) {
    message = `@${u} is reserved, and you have proved every claim it opens for: ${unlock.met.map(describeRequirement).join(' and ')}.`;
  } else if (reservedWord) message = 'That handle is reserved by the system and cannot be claimed.';
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
  // An unlockable handle has its OWN steps, and they are the only ones that
  // work. Falling through to the generic advice below would tell somebody to go
  // and verify a key-platform account, which does nothing for a reserved name.
  if (unlock && !unlock.unlocked) {
    for (const req of unlock.missing) {
      howToQualify.push(
        req.kind === 'domain'
          ? `Prove ${describeRequirement(req)} via the domain challenge.`
          : `Verify ${describeRequirement(req)}.`,
      );
    }
  } else if (!qualifies && !reservedWord && isValidFormat(u)) {
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

  return { username: u, valid, reservedWord, tier, score, basis, qualifies, message, howToQualify, unlock };
}
