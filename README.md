# QR Kit Fingerprint

Attribute phishing kits by their QR encoder's behavioral quirks — a technique
that survives into the final image and identifies the toolkit behind a lure.

## Theory

QR generator libraries differ in two behavioral choices that act as a toolkit
fingerprint:

1. **Version selection** — a spec-faithful encoder picks the smallest version
   that fits the payload at the chosen EC level. Sloppy toolkits overshoot
   (e.g. version 6 for a 45-byte payload that fits in version 4).
2. **Mask selection** — the QR spec defines 8 data masks and 4 penalty rules;
   a proper encoder evaluates all 8 and picks the lowest-penalty mask. Cheap
   toolkits hardcode a mask or pick badly.

## Usage

```
qr-fingerprint.py <image> [--save-ref name] [--compare <ref.json>]
```

Produces a fingerprint JSON (format info, penalty evaluation across all 8
masks). `--compare` scores 0–100 against a reference fingerprint — same
toolkit, same behavioral signature.

Requires: opencv-python-headless, numpy, Pillow.

## Contents

- `qr-fingerprint.py` — the fingerprinting tool
- `ref-pow-3942.json` — reference fingerprint from the POW-3942 lure
- `pow-3942-qr.gif` — original lure image (defensive sample)
- `pow-3942-report.md` — case report

Defensive use only: kit attribution for takedown and reporting workflows.
