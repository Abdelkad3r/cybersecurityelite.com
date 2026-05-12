# OG image auto-generation assets

Drop two files here to enable per-article Open Graph image generation:

## 1. `base.png` — the canvas (1200×630)

Build a single dark canvas with branding (logo, gradient, etc.) but NO text.
The partial overlays section + title + URL automatically.

Easiest way: convert the existing brand SVG:

```bash
# Requires ImageMagick (brew install imagemagick / apt install imagemagick)
convert -background "#000000" -density 144 \
  static/images/og-default.svg \
  -resize 1200x630! \
  assets/og/base.png
```

Or use any design tool — Figma, Photoshop, even keynote — to export a
1200×630 PNG. The text overlay rendered by Hugo will land at:
  - `(80, 80)`  small uppercase section name in cyan
  - `(80, 190)` article title in white (up to ~2 lines)
  - `(80, 540)` `cybersecurityelite.com` URL in muted gray

So leave that area of the design empty.

## 2. `font.ttf` — the typeface

We recommend Inter Bold. One-line install:

```bash
curl -L -o assets/og/font.ttf \
  https://github.com/rsms/inter/raw/master/docs/font-files/Inter-Bold.ttf
```

Or any TTF/OTF you prefer.

## How it works

`layouts/partials/og_image.html`:
- Front-matter `cover.image` always wins (per-article override)
- Otherwise: if both `base.png` and `font.ttf` exist, Hugo's
  `images.Text` filter composites the article title onto the base
- Otherwise: falls back to `/images/og-default.svg`

Generated images live at `/og/base_hugo_…[hash].png` per article and are
cache-busted automatically.
