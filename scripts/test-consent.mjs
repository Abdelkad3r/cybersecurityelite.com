import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import consentWorker, { getConsentRegion } from './cloudflare-consent-worker.mjs';

for (const country of ['SE', 'DE', 'IS', 'LI', 'NO', 'GB', 'CH']) {
  assert.equal(getConsentRegion(country), 'eu', `${country} must use Google CMP`);
}
for (const country of ['US', 'MA', 'CA', 'AU']) {
  assert.equal(getConsentRegion(country), 'other', `${country} must use custom consent`);
}
for (const country of [undefined, null, '', 'XX1', 'swe', 'T1', 'XX', 'A1']) {
  assert.equal(getConsentRegion(country), 'unknown', 'invalid edge data must fail closed');
}

const home = await readFile('public/index.html', 'utf8');
const privacy = await readFile('public/privacy-policy/index.html', 'utf8');
const consent = await readFile('layouts/partials/cookie-consent.html', 'utf8');
const head = await readFile('layouts/partials/extend_head.html', 'utf8');
const footer = await readFile('layouts/partials/extend_footer.html', 'utf8');

assert.ok(/consent","default"/.test(home), 'Consent Mode default must be present');
assert.ok(/analytics_storage:["']denied["'],ad_storage:["']denied["'],ad_user_data:["']denied["'],ad_personalization:["']denied["']/.test(home), 'all Consent Mode v2 defaults must be denied');
assert.ok(/<meta name=cse-adsense-cmp content="ca-pub-8915981048230727">/.test(home), 'regional CMP marker must use existing publisher ID');
assert.ok(home.indexOf('gtag("consent","default"') < home.indexOf('cse-adsense-cmp'), 'CMP marker must follow denied defaults');
assert.ok(!/adsbygoogle\.js/.test(home), 'static HTML must not load the publisher tag outside its region gate');
assert.ok(!/cse-adsense-cmp/.test(privacy), 'privacy-policy page must not request the AdSense tag');
assert.ok(!/adsbygoogle\.js/.test(privacy), 'privacy-policy page must not load consent-required ad tags');
assert.ok(!/<ins[^>]+adsbygoogle|adsbygoogle\.push/.test(home), 'no AdSense ad placements are configured');
assert.ok(!/profitableratecpmnetwork\.com\/ee\//.test(home), 'Social Bar must remain disabled');
assert.ok(/consentv2/.test(footer), 'Clarity Consent V2 must be wired');
assert.ok(/region === 'other'/.test(consent), 'Adsterra consent remains limited to non-regulated regions');
assert.ok(/showFallbackChoices/.test(consent), 'EU visitors get an analytics-only fallback if Google CMP does not respond');
assert.ok(/Adsterra ads stay disabled in this region/.test(consent), 'EU fallback discloses that Adsterra stays off');
assert.ok(/if \(region !== 'other'\) return/.test(consent), 'Adsterra calls are blocked outside known non-regulated regions');
assert.ok(/window\.location\.pathname !== '\/privacy-policy\//.test(consent), 'CMP fallback does not appear on the page that intentionally omits the Google tag');
assert.ok(/backup choice panel may appear after a short delay/.test(await readFile('content/privacy.md', 'utf8')), 'privacy policy documents the analytics-only CMP fallback');
assert.ok(/script\.onerror = function/.test(footer), 'Adsterra loader releases its retry lock after a failed request');
assert.ok(/window\.__CSE_CONSENT_REGION__ !== 'other'/.test(footer), 'Adsterra source rejects non-regulated regions');
assert.ok(/CONSENT_MODE_DATA_READY/.test(consent), 'Google tags must wait for Google CMP consent data');
assert.ok(/analyticsStoragePurposeConsentStatus === statuses\.GRANTED/.test(consent), 'Google Analytics must require granted analytics consent');
assert.ok(/cse_consent_v4/.test(consent), 'custom consent storage must use the current key');
assert.ok(/name="cse-adsense-cmp" content="\{\{ \$adsensePublisherID \}\}"/.test(head));

for (const match of home.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
  const [, attributes, source] = match;
  if (/application\/ld\+json|type=module/.test(attributes)) continue;
  if (source.trim()) new vm.Script(source, { filename: 'generated-inline-script.js' });
}

const managerScript = consent.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(managerScript, 'custom consent controller script must exist');

function createRuntime(region, savedConsent) {
  const ids = ['cse-cb', 'cse-modal', 'cse-tog-analytics', 'cse-tog-ads', 'cse-mclose',
    'cse-btn-accept', 'cse-btn-reject', 'cse-btn-manage', 'cse-modal-cancel', 'cse-modal-save', 'cse-eu-fallback-note'];
  const elements = Object.fromEntries(ids.map((id) => [id, {
    checked: false,
    disabled: false,
    hidden: true,
    textContent: '',
    events: {},
    classes: new Set(),
    classList: {
      add(name) { elements[id].classes.add(name); },
      remove(name) { elements[id].classes.delete(name); },
      contains(name) { return elements[id].classes.has(name); }
    },
    addEventListener(type, fn) { elements[id].events[type] = fn; },
    focus() {},
    querySelectorAll() { return []; }
  }]));
  const listeners = {};
  const stored = new Map(savedConsent ? [['cse_consent_v4', JSON.stringify(savedConsent)]] : []);
  const fcQueue = [];
  const timers = [];
  let nextTimer = 1;
  const advertisingCalls = [];
  const win = {
    __CSE_CONSENT_REGION__: region,
    location: { pathname: '/', search: '', hash: '', reloads: 0, reload() { this.reloads++; }, assign() {} },
    history: { replaceState() {} },
    googlefc: { callbackQueue: { push(item) { fcQueue.push(item); return fcQueue.length; } } },
    gtag() {},
    __cseGA4Loaded: false,
    __cseClarityLoaded: false,
    __cseAdsterraLoaded: false,
    __cseFireGA4() { this.__cseGA4Loaded = true; },
    __cseFireClarity() { this.__cseClarityLoaded = true; },
    __cseFireAdsterra() { advertisingCalls.push(true); this.__cseAdsterraLoaded = true; },
    setTimeout(fn, delay) { const timer = { id: nextTimer++, fn, delay, cleared: false }; timers.push(timer); return timer.id; },
    clearTimeout(id) { const timer = timers.find((candidate) => candidate.id === id); if (timer) timer.cleared = true; }
  };
  const doc = {
    body: { classList: { contains() { return false; } } },
    getElementById(id) { return elements[id]; },
    addEventListener(type, fn) { listeners[type] = fn; }
  };
  const context = {
    window: win,
    document: doc,
    localStorage: {
      getItem(key) { return stored.get(key) || null; },
      setItem(key, value) { stored.set(key, value); },
      removeItem(key) { stored.delete(key); }
    },
    URLSearchParams,
    Date,
    JSON,
    Array
  };
  vm.runInNewContext(managerScript, context);
  return { elements, listeners, stored, fcQueue, timers, advertisingCalls, win };
}

const other = createRuntime('other');
assert.ok(other.elements['cse-cb'].classes.has('cse-show'), 'non-regulated visitor sees the custom banner');
assert.equal(other.win.__cseGA4Loaded, false, 'optional scripts stay off before choice');
other.elements['cse-btn-manage'].events.click();
assert.equal(other.elements['cse-tog-analytics'].checked, false, 'Manage starts analytics denied');
assert.equal(other.elements['cse-tog-ads'].checked, false, 'Manage starts advertising denied');
other.elements['cse-modal-save'].events.click();
assert.equal(JSON.parse(other.stored.get('cse_consent_v4')).analytics, false, 'saving defaults does not grant analytics');

const accepted = createRuntime('other');
accepted.elements['cse-btn-accept'].events.click();
assert.equal(accepted.win.__cseGA4Loaded, true, 'Accept All unlocks analytics');
assert.equal(JSON.parse(accepted.stored.get('cse_consent_v4')).advertising, true, 'Accept All records advertising consent');
assert.equal(accepted.advertisingCalls.length, 1, 'non-regulated Accept All starts the Adsterra loader');
accepted.elements['cse-btn-reject'].events.click();
assert.equal(accepted.win.location.reloads, 1, 'Reject All reloads to stop already-loaded optional scripts');

const unknown = createRuntime('unknown');
assert.equal(unknown.elements['cse-cb'].classes.has('cse-show'), false, 'unknown geography fails closed without a custom prompt');
assert.equal(unknown.win.__cseGA4Loaded, false, 'unknown geography cannot start analytics');

const euFallback = createRuntime('eu');
assert.equal(euFallback.elements['cse-cb'].classes.has('cse-show'), false, 'European visitor initially waits for Google CMP');
assert.equal(euFallback.win.__cseGA4Loaded, false, 'Google tags wait until Google CMP data is ready');
assert.equal(euFallback.timers.at(-1).delay, 8000, 'EU fallback waits for the Google CMP response');
euFallback.timers.at(-1).fn();
assert.equal(euFallback.elements['cse-cb'].classes.has('cse-show'), true, 'EU visitor sees backup choices if Google CMP does not respond');
assert.match(euFallback.elements['cse-eu-fallback-note'].textContent, /Adsterra ads stay disabled/);
euFallback.elements['cse-btn-accept'].events.click();
assert.equal(JSON.parse(euFallback.stored.get('cse_consent_v4')).analytics, true, 'EU fallback stores an explicit analytics choice');
assert.equal(JSON.parse(euFallback.stored.get('cse_consent_v4')).advertising, false, 'EU fallback does not grant advertising consent');
assert.equal(euFallback.win.__cseGA4Loaded, true, 'EU fallback starts analytics only after opt-in');
assert.equal(euFallback.advertisingCalls.length, 0, 'EU fallback never starts Adsterra');

const euCmpAvailable = createRuntime('eu');
euCmpAvailable.win.__tcfapi = (_command, _version, callback) => { euCmpAvailable.tcfListener = callback; };
euCmpAvailable.fcQueue.find((item) => item.CONSENT_API_READY)?.CONSENT_API_READY();
euCmpAvailable.tcfListener({ eventStatus: 'cmpuishown' }, true);
assert.equal(euCmpAvailable.timers.at(-1).cleared, true, 'Google CMP response cancels the fallback timer');
euCmpAvailable.timers.at(-1).fn();
assert.equal(euCmpAvailable.elements['cse-cb'].classes.has('cse-show'), false, 'Google CMP and fallback are never visible together');
assert.equal(euCmpAvailable.elements['cse-tog-ads'].disabled, true, 'Adsterra stays unavailable in regulated regions');

const eu = createRuntime('eu');
let consentValues = {
  analyticsStoragePurposeConsentStatus: 2,
  adStoragePurposeConsentStatus: 2
};
eu.win.googlefc.ConsentModePurposeStatusEnum = {
  GRANTED: 1,
  DENIED: 2
};
eu.win.googlefc.getGoogleConsentModeValues = () => consentValues;
let tcfListener;
eu.win.__tcfapi = (_command, _version, callback) => { tcfListener = callback; };
const dataReady = eu.fcQueue.find((item) => item.CONSENT_MODE_DATA_READY)?.CONSENT_MODE_DATA_READY;
const apiReady = eu.fcQueue.find((item) => item.CONSENT_API_READY)?.CONSENT_API_READY;
dataReady();
apiReady();
assert.equal(eu.win.__cseGA4Loaded, false, 'denied European consent does not load analytics');
let revocationPrompts = 0;
eu.win.googlefc.showRevocationMessage = () => { revocationPrompts++; };
eu.win.cseConsent.open();
eu.fcQueue.at(-1)();
assert.equal(revocationPrompts, 1, 'European settings link reopens the Google CMP revocation flow');
consentValues = { analyticsStoragePurposeConsentStatus: 1, adStoragePurposeConsentStatus: 2 };
tcfListener({ eventStatus: 'useractioncomplete' }, true);
eu.fcQueue.at(-1).CONSENT_MODE_DATA_READY();
assert.equal(eu.win.__cseGA4Loaded, true, 'Google CMP analytics grant unlocks GA4');
assert.equal(eu.win.__cseClarityLoaded, true, 'Google CMP analytics grant unlocks Clarity');
assert.equal(eu.win.__cseAdsterraLoaded, false, 'Adsterra remains disabled in the regulated region');
consentValues = { analyticsStoragePurposeConsentStatus: 2, adStoragePurposeConsentStatus: 2 };
tcfListener({ eventStatus: 'useractioncomplete' }, true);
eu.fcQueue.at(-1).CONSENT_MODE_DATA_READY();
assert.equal(eu.win.location.reloads, 1, 'revoking loaded analytics reloads into the denied state');

const priorFetch = globalThis.fetch;
const priorRewriter = globalThis.HTMLRewriter;
const htmlFixture = '<html><head><script>gtag("consent","default",{analytics_storage:"denied"});</script><meta name="cse-adsense-cmp" content="ca-pub-8915981048230727"></head><body>ok</body></html>';

async function withWorkerMocks({ body = htmlFixture, contentType = 'text/html; charset=utf-8', status = 200, headers = {}, fetchError, transformError }, test) {
  let fetchArgs;
  globalThis.fetch = async (...args) => {
    fetchArgs = args;
    if (fetchError) throw fetchError;
    return new Response(body, {
      status,
      headers: { 'content-type': contentType, etag: 'old-etag', ...headers }
    });
  };
  globalThis.HTMLRewriter = class {
    constructor() { this.handlers = []; }
    on(selector, handler) { this.handlers.push({ selector, handler }); return this; }
    async transform(response) {
      if (transformError) throw transformError;
      const handlers = new Map(this.handlers.map(({ selector, handler }) => [selector, handler]));
      let injected = '';
      let afterMarker = '';
      let html = await response.text();
      const headMatch = html.match(/<head[^>]*>/i);
      if (headMatch && handlers.has('head')) {
        handlers.get('head').element({ prepend(value) { injected = value; } });
        html = html.replace(headMatch[0], `${headMatch[0]}${injected}`);
      }
      const markerMatch = html.match(/<meta name="cse-adsense-cmp" content="([^"]*)">/i);
      if (markerMatch && handlers.has('meta[name="cse-adsense-cmp"]')) {
        handlers.get('meta[name="cse-adsense-cmp"]').element({
          getAttribute(name) { return name === 'content' ? markerMatch[1] : null; },
          after(value) { afterMarker = value; }
        });
        html = html.replace(markerMatch[0], `${markerMatch[0]}${afterMarker}`);
      }
      return new Response(html, { status: response.status, headers: response.headers });
    }
  };
  try {
    await test({ getFetchArgs: () => fetchArgs });
  } finally {
    globalThis.fetch = priorFetch;
    globalThis.HTMLRewriter = priorRewriter;
  }
}

function workerRequest(method = 'GET', ...countryValues) {
  const country = countryValues.length ? countryValues[0] : 'SE';
  return { method, cf: country === undefined ? {} : { country } };
}

const staticResources = [
  ['robots.txt', 'text/plain; charset=utf-8', 'User-agent: *\\nAllow: /'],
  ['sitemap.xml', 'application/xml', '<urlset></urlset>'],
  ['index.xml', 'application/xml', '<rss></rss>'],
  ['feed.xml', 'application/atom+xml', '<feed></feed>'],
  ['app.css', 'text/css', 'body{color:#fff}'],
  ['app.js', 'application/javascript', 'console.log("asset")'],
  ['logo.svg', 'image/svg+xml', '<svg></svg>'],
  ['cover.webp', 'image/webp', 'image-bytes']
];
for (const [path, contentType, body] of staticResources) {
  await withWorkerMocks({ body, contentType, headers: { 'cache-control': 'public, max-age=86400' } }, async ({ getFetchArgs }) => {
    const response = await consentWorker.fetch(workerRequest());
    assert.equal(await response.text(), body, `${path} body must pass through unchanged`);
    assert.equal(response.status, 200, `${path} status must pass through unchanged`);
    assert.equal(response.headers.get('content-type'), contentType, `${path} content type must pass through unchanged`);
    assert.equal(response.headers.get('cache-control'), 'public, max-age=86400', `${path} cache policy must pass through unchanged`);
    assert.equal(getFetchArgs().length, 1, `${path} fetch must not override normal Cloudflare caching`);
  });
}

await withWorkerMocks({ headers: { vary: 'Accept-Encoding' } }, async ({ getFetchArgs }) => {
  const routed = await consentWorker.fetch(workerRequest('GET', 'SE'));
  const euHTML = await routed.text();
  assert.match(euHTML, /__CSE_CONSENT_REGION__="eu"/);
  assert.match(euHTML, /adsbygoogle\.js\?client=ca-pub-8915981048230727/);
  assert.ok(euHTML.indexOf('consent","default"') < euHTML.indexOf('adsbygoogle.js?client='), 'publisher tag must follow denied defaults');
  assert.match(routed.headers.get('cache-control'), /private, no-store/);
  assert.match(routed.headers.get('vary'), /Accept-Encoding/);
  assert.match(routed.headers.get('vary'), /CF-IPCountry/);
  assert.equal(routed.headers.get('etag'), null, 'transformed HTML must not retain the origin ETag');
  assert.equal(routed.headers.get('content-length'), null, 'transformed HTML must not retain the origin length');
  assert.equal(getFetchArgs().length, 1, 'HTML fetch must rely on the configured HTML bypass rule, not force a TTL');
});

for (const [country, expected] of [['GB', 'eu'], ['CH', 'eu'], ['US', 'other'], ['MA', 'other'], [undefined, 'unknown'], ['T1', 'unknown']]) {
  await withWorkerMocks({}, async () => {
    const response = await consentWorker.fetch(workerRequest('GET', country));
    const html = await response.text();
    assert.match(html, new RegExp(`__CSE_CONSENT_REGION__="${expected}"`), `${country || 'missing country'} must route to ${expected}`);
    if (expected !== 'eu') assert.doesNotMatch(html, /adsbygoogle\.js/, `${expected} regions must not load the CMP publisher tag`);
  });
}

for (const request of [workerRequest('HEAD', 'SE'), workerRequest('POST', 'SE')]) {
  await withWorkerMocks({}, async () => {
    const response = await consentWorker.fetch(request);
    assert.equal(await response.text(), htmlFixture, `${request.method} HTML should remain untransformed`);
    assert.equal(response.headers.get('cache-control'), null, `${request.method} should retain origin headers`);
  });
}

await withWorkerMocks({ contentType: 'text/html', status: 404 }, async () => {
  const response = await consentWorker.fetch(workerRequest());
  assert.equal(response.status, 404, 'non-200 HTML status should pass through');
  assert.equal(await response.text(), htmlFixture, 'non-200 HTML body should pass through');
});

await withWorkerMocks({ fetchError: new Error('simulated origin failure') }, async () => {
  const response = await consentWorker.fetch(workerRequest());
  assert.equal(response.status, 502, 'origin fetch failure should return 502');
  assert.match(response.headers.get('content-type'), /text\/plain/);
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.doesNotMatch(await response.text(), /<script|adsbygoogle|gtag|clarity|adsterra/i, 'fetch failure response must contain no tracking code');
});

for (const failure of [
  { transformError: new Error('simulated HTML transform failure') },
  { body: '<html><body>missing head</body></html>' }
]) {
  await withWorkerMocks(failure, async () => {
    const response = await consentWorker.fetch(workerRequest('GET', 'GB'));
    assert.equal(response.status, 503, 'HTML transformation failure should return 503');
    assert.match(response.headers.get('content-type'), /text\/plain/);
    assert.match(response.headers.get('cache-control'), /no-store/);
    assert.doesNotMatch(await response.text(), /<script|adsbygoogle|gtag|clarity|adsterra/i, 'transform failure response must contain no tracking code');
  });
}

console.log('Consent routing, cache pass-through, fail-closed errors, and generated-site checks passed.');
