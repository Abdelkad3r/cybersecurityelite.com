# Cloudflare consent region routing

Hugo's consent controller uses `window.__CSE_CONSENT_REGION__`, which this Worker
injects from Cloudflare's request country (`request.cf.country`). For EEA/UK/Swiss
visitors, it also inserts Google's official AdSense publisher tag after the
Consent Mode denied defaults, using the publisher ID emitted by Hugo in the
`cse-adsense-cmp` meta marker. It does not insert that tag for other regions. The
Worker maps EEA member states plus Iceland, Liechtenstein, Norway, the UK, and
Switzerland to `eu`; all other valid country codes map to `other`. Missing or
malformed edge country data maps to `unknown`, which keeps both custom consent UI
and optional analytics/advertising disabled.

Only successful `GET` HTML responses are transformed. Their output is marked
`private, no-store, max-age=0`, has its stale entity tag and content length removed,
and includes `CF-IPCountry` in `Vary` as defense in depth. The Worker does not set
fetch cache overrides: `robots.txt`, sitemaps, feeds, scripts, stylesheets, images,
and other non-HTML responses pass through with their status, body, and cache headers
unchanged, using normal Cloudflare cache rules. The HTML cache rule should bypass
HTML only; confirm that it does not bypass static-resource caching. Never rely on
`Vary` instead of the HTML `no-store` policy for country isolation.

If fetching the origin fails, the Worker returns a plain-text 502 with `no-store`.
If HTML rewriting fails or a successful HTML response has no `<head>`, it returns a
plain-text 503 with `no-store`. Those responses contain no page scripts, CMP tag, or
tracking code. The rewritten HTML body is consumed before response so streaming
rewrite errors are caught before any partial transformed page is sent. This adds
some buffering for HTML only; compare production TTFB and Worker error metrics in
staging.

## Staged rollout checklist

1. Confirm the apex DNS record is proxied and that the Cloudflare account can attach
   the `cybersecurityelite.com/*` route. The current Wrangler route covers the apex,
   not `www`; confirm `www` redirects to the HTTPS apex before relying on this route.
2. Confirm the Cloudflare HTML Cache Rule bypasses HTML responses only. Static files
   must retain their normal cache policy. Purge previously cached HTML before
   testing. Review Cache Rules, Page Rules, and Response Rules for any override.
3. Use a staging hostname/route or `wrangler dev` with mocked country data first.
   Run `npm run test:consent`, then verify EEA, UK, CH, non-European, and unknown
   mappings. A client-supplied country header must not be used to simulate a
   production visitor; test production routing with real regional egress.
4. Deploy the Worker route before the Hugo site revision. Until the Hugo marker is
   published, the Worker should inject the region marker only and must not insert
   `adsbygoogle.js`. Verify static files and XML/text resources retain body,
   content type, and cache headers.
5. Publish the Hugo site revision through GitHub Pages. Test with clean browser
   storage from EEA, UK, Switzerland, non-European, and unknown-country contexts.
   Check that EEA users see only Google CMP; the publisher tag follows denied
   Consent Mode defaults; GA4 and Clarity wait for analytics consent; Adsterra
   remains disabled in regulated regions; and non-European users see only the
   custom banner. Unknown routing must load no optional services.
6. Inspect browser network requests before and after each consent choice. The
   publisher script must be present only for the European CMP path. Confirm no
   ad-serving requests/visible placements occur while Auto Ads are disabled and
   no ad units are configured. Confirm GA4/Clarity and Adsterra appear only after
   their respective consent, then test revocation.
7. Check the response headers and Cloudflare cache analytics for multiple regions:
   every transformed HTML response must be `no-store`, and no cached HTML variant
   may be served across country routes. Confirm `robots.txt`, XML sitemaps, feeds,
   CSS, JavaScript, and images are still cacheable according to their normal rules.
   Monitor Worker exceptions, 502/503 responses, and TTFB before widening traffic.

## Rollback

For a Worker-only issue, roll back the Worker to its last known-good version or
remove the production route. If the new Hugo revision is already live, the missing
edge marker makes its controller default to `unknown`, so optional tracking stays
off; the consent interface will also be absent until recovery. Restore the previous
Pages artifact/revert the Pages commit promptly, purge cached HTML, and verify the
old page and consent UI from each test region. If the Worker itself risks leaking
country output, disable its route immediately, restore the prior Pages revision,
then purge HTML and retest. GitHub Pages deployment and Cloudflare Worker
deployment are separate; the Pages workflow does not deploy this Worker.

Keep Auto Ads disabled in the AdSense account before enabling the regional
publisher tag. This repository contains no AdSense ad unit markup and does not
enable Auto Ads, but account-level Auto Ads settings are outside the Hugo source.

After review, deploy from the repository root with Cloudflare Wrangler after
authenticating the account that manages the `cybersecurityelite.com` zone. Use
Node.js 22 or later. Validate the package before the production route is attached:

```sh
npx wrangler deploy --dry-run --config wrangler.toml
npx wrangler deploy --config wrangler.toml
```

Before enabling the route, confirm the existing published European regulations
message is selected for this AdSense site and has its required user choices. The
Worker does not create, edit, or publish CMP messages.
