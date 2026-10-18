const REGULATED_COUNTRIES = new Set([
  // EEA: EU member states, Iceland, Liechtenstein, and Norway.
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR',
  'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
  'SI', 'ES', 'SE', 'IS', 'LI', 'NO',
  // United Kingdom and Switzerland.
  'GB', 'CH'
]);
const UNKNOWN_COUNTRIES = new Set(['A1', 'T1', 'XX']);

export function getConsentRegion(country) {
  if (typeof country !== 'string' || !/^[A-Z]{2}$/.test(country) || UNKNOWN_COUNTRIES.has(country)) return 'unknown';
  return REGULATED_COUNTRIES.has(country) ? 'eu' : 'other';
}

function failClosed(status, message) {
  return new Response(message, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-robots-tag': 'noindex'
    }
  });
}

async function injectRegion(response, region) {
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete('etag');
  headers.set('cache-control', 'private, no-store, max-age=0');
  const vary = (headers.get('vary') || '').split(',').map((value) => value.trim()).filter(Boolean);
  if (!vary.includes('*') && !vary.some((value) => value.toLowerCase() === 'cf-ipcountry')) {
    vary.push('CF-IPCountry');
  }
  if (vary.length) headers.set('vary', vary.join(', '));

  const regionMarker = `<script>window.__CSE_CONSENT_REGION__=${JSON.stringify(region)};</script>`;
  let foundHead = false;
  const rewriter = new HTMLRewriter()
    .on('head', {
      element(element) {
        foundHead = true;
        element.prepend(regionMarker, { html: true });
      }
    });

  if (region === 'eu') {
    rewriter.on('meta[name="cse-adsense-cmp"]', {
      element(element) {
        const publisherID = element.getAttribute('content') || '';
        if (!/^ca-pub-\d+$/.test(publisherID)) return;
        const cmpBootstrap = '<script>window.googlefc=window.googlefc||{};window.googlefc.callbackQueue=window.googlefc.callbackQueue||[];</script>';
        const publisherTag = `<script async crossorigin="anonymous" src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${publisherID}"></script>`;
        element.after(cmpBootstrap + publisherTag, { html: true });
      }
    });
  }

  const transformed = await rewriter.transform(new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    }));

  // Consume the rewritten HTML before returning so body-stream/handler failures
  // are caught here. On failure, the caller returns a plain-text 503 with no
  // application scripts, consent UI, or tracking code.
  const body = await transformed.text();
  if (!foundHead) throw new Error('HTML response did not contain a head element');
  return new Response(body, {
    status: transformed.status,
    statusText: transformed.statusText,
    headers: transformed.headers
  });
}

export default {
  async fetch(request) {
    let originResponse;
    try {
      // Leave cache policy to Cloudflare's normal rules for static resources.
      // The transformed HTML response is marked no-store below.
      originResponse = await fetch(request);
    } catch (_) {
      return failClosed(502, 'The site is temporarily unavailable. Please try again shortly.');
    }

    const contentType = (originResponse.headers.get('content-type') || '').toLowerCase();
    if (request.method !== 'GET' || originResponse.status !== 200 || !contentType.includes('text/html')) {
      return originResponse;
    }

    const country = request.cf && request.cf.country;
    try {
      return await injectRegion(originResponse, getConsentRegion(country));
    } catch (_) {
      return failClosed(503, 'The page is temporarily unavailable. Please try again shortly.');
    }
  }
};
