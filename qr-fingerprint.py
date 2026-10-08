#!/usr/bin/env python3
"""
qr-fingerprint.py — QR code generator fingerprinting for phishing-kit correlation.

Theory: QR generator libraries differ in two behavioral choices that survive
into the final image and act as a toolkit fingerprint:
  1. VERSION SELECTION — a spec-faithful encoder picks the smallest version
     that fits the payload at the chosen EC level. Sloppy toolkits overshoot
     (e.g. version 6 for a 45-byte payload that fits in version 4).
  2. MASK SELECTION — the QR spec defines 8 data masks and 4 penalty rules;
     a proper encoder evaluates all 8 and picks the lowest-penalty mask.
     Cheap toolkits hardcode a mask or pick badly.

Usage:
  qr-fingerprint.py <image> [--save-ref name] [--compare <ref.json>]

Requires: opencv-python-headless, numpy, Pillow (uses ~/workspace/scam-intel/qrvenv).
"""
import sys, os, json, math
import cv2
import numpy as np

# Byte-mode data capacity (codewords) per version / EC level (L, M, Q, H)
CAPACITY = {
    1: (19, 16, 13, 9), 2: (34, 28, 22, 16), 3: (55, 44, 34, 26),
    4: (80, 64, 48, 36), 5: (108, 86, 62, 46), 6: (136, 108, 76, 60),
    7: (156, 124, 88, 66), 8: (194, 154, 110, 86), 9: (232, 182, 132, 100),
    10: (274, 216, 154, 122),
}
EC_IDX = {'L': 0, 'M': 1, 'Q': 2, 'H': 3}
EC_BITS = {'01': 'L', '00': 'M', '11': 'Q', '10': 'H'}
ALIGN_POS = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
             7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}


def extract_qr(image_path):
    """Detect QR, warp to straight-on view, return (matrix bool array, version, module_px)."""
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise SystemExit(f'cannot read {image_path}')
    det = cv2.QRCodeDetector()
    data, bbox, straight = det.detectAndDecode(img)
    if bbox is None:
        raise SystemExit('no QR code detected')
    # Determine module count from the straightened warp if it looks like 1px/module,
    # else fall back to timing-pattern measurement on the warped image.
    sq = straight
    if len(sq.shape) == 3:
        sq = cv2.cvtColor(sq, cv2.COLOR_BGR2GRAY)
    n = sq.shape[0]
    # OpenCV warps to a fixed internal size; re-derive modules via timing pattern.
    _, th = cv2.threshold(sq, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    # timing pattern sits at row 6 of the module grid; find module size from finder ratio instead
    # walk a horizontal line through upper finder zone and use 1:1:3:1:1 ratio
    h = th.shape[0]
    best = None
    for fy in np.linspace(0.08, 0.25, 6):
        row = th[int(h * fy)]
        xs = np.where(row < 128)[0]
        if len(xs) < 10:
            continue
        seg = row[xs[0]:xs[-1] + 1]
        runs, cur = [], 1
        for i in range(1, len(seg)):
            if seg[i] == seg[i - 1]:
                cur += 1
            else:
                runs.append(cur); cur = 1
        runs.append(cur)
        # look for 1:1:3:1:1 pattern at the start (left finder)
        if len(runs) >= 5:
            u = sum(runs[:5]) / 7.0
            ratios = [r / u for r in runs[:5]]
            if all(abs(a - b) < 0.6 for a, b in zip(ratios, [1, 1, 3, 1, 1])):
                mods = round((xs[-1] - xs[0] + 1) / u)
                if 21 <= mods <= 177 and mods % 4 == 1:
                    best = (mods, u * (img.shape[1] / th.shape[1]))
                    break
    if best is None:
        # fallback: timing pattern count
        raise SystemExit('could not determine module count')
    modules, module_px = best
    version = (modules - 21) // 4 + 1
    # Build clean module matrix by warping bbox to modules x modules and sampling centers
    src = bbox.reshape(4, 2).astype(np.float32)  # tl, tr, br, bl (opencv order)
    # opencv bbox order: top-left, top-right, bottom-right, bottom-left
    dst = np.array([[0, 0], [modules * 8, 0], [modules * 8, modules * 8],
                    [0, modules * 8]], dtype=np.float32)
    M = cv2.getPerspectiveTransform(src, dst)
    warped = cv2.warpPerspective(img, M, (modules * 8, modules * 8))
    _, wth = cv2.threshold(warped, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    mat = np.zeros((modules, modules), dtype=bool)
    for r in range(modules):
        for c in range(modules):
            mat[r, c] = wth[r * 8 + 4, c * 8 + 4] < 128
    return mat, version, modules, module_px, data


def read_format_info(mat):
    """Read EC level + mask from format info near top-left finder."""
    n = mat.shape[0]
    pos = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
           (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    raw = ''.join('1' if mat[r, c] else '0' for r, c in pos)
    mask = '101010000010010'
    unmasked = ''.join(str(int(b) ^ int(k)) for b, k in zip(raw, mask))
    ec = EC_BITS.get(unmasked[:2], '?')
    maskpat = int(unmasked[2:5], 2)
    return ec, maskpat, raw


def function_modules(n, version):
    """Boolean mask: True where modules are function patterns (not data)."""
    f = np.zeros((n, n), dtype=bool)
    # finders + separators
    f[0:9, 0:9] = True
    f[0:9, n - 8:n] = True
    f[n - 8:n, 0:9] = True
    # timing
    f[6, :] = True
    f[:, 6] = True
    # alignment patterns
    for cy in ALIGN_POS.get(version, []):
        for cx in ALIGN_POS.get(version, []):
            if not ((cx < 9 and cy < 9) or (cx > n - 9 and cy < 9) or (cx < 9 and cy > n - 9)):
                f[cy - 2:cy + 3, cx - 2:cx + 3] = True
    # format info zones
    f[0:9, 8] = True; f[8, 0:9] = True
    f[n - 8:n, 8] = True; f[8, n - 8:n] = True
    # dark module
    f[n - 7, 8] = True
    if version >= 7:
        f[0:6, n - 11:n - 8] = True
        f[n - 11:n - 8, 0:6] = True
    return f


def apply_mask(mat, maskpat, func):
    """Return copy of matrix with mask pattern applied to data modules."""
    n = mat.shape[0]
    out = mat.copy()
    rr, cc = np.nonzero(~func)
    if maskpat == 0:
        cond = (rr + cc) % 2 == 0
    elif maskpat == 1:
        cond = rr % 2 == 0
    elif maskpat == 2:
        cond = cc % 3 == 0
    elif maskpat == 3:
        cond = (rr + cc) % 3 == 0
    elif maskpat == 4:
        cond = (rr // 2 + cc // 3) % 2 == 0
    elif maskpat == 5:
        cond = ((rr * cc) % 2 + (rr * cc) % 3) == 0
    elif maskpat == 6:
        cond = ((rr * cc) % 2 + (rr + cc) % 3) % 2 == 0
    else:
        cond = ((rr + cc) % 2 + (rr * cc) % 3) % 2 == 0
    out[rr[cond], cc[cond]] = ~out[rr[cond], cc[cond]]
    return out


def penalty(mat):
    """QR spec data-mask penalty score (4 rules). Lower is better."""
    n = mat.shape[0]
    score = 0
    # Rule 1: runs of 5+ same color
    for line in list(mat) + list(mat.T):
        run, last = 1, line[0]
        for v in line[1:]:
            if v == last:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, last = 1, v
        if run >= 5:
            score += 3 + (run - 5)
    # Rule 2: 2x2 blocks
    for r in range(n - 1):
        for c in range(n - 1):
            if mat[r, c] == mat[r, c + 1] == mat[r + 1, c] == mat[r + 1, c + 1]:
                score += 3
    # Rule 3: finder-like patterns 10111010000 / 00001011101
    pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat2 = pat1[::-1]
    for line in list(mat.astype(int)) + list(mat.T.astype(int)):
        for i in range(len(line) - 10):
            w = list(line[i:i + 11])
            if w == pat1 or w == pat2:
                score += 40
    # Rule 4: dark ratio deviation from 50%
    dark_pct = 100.0 * np.sum(mat) / mat.size
    score += 10 * int(abs(dark_pct - 50) // 5)
    return score


def min_version(payload_len, ec):
    """Smallest version fitting payload_len bytes (byte mode) at EC level."""
    need = payload_len + 2  # mode indicator + char count overhead
    for v in range(1, 11):
        if CAPACITY[v][EC_IDX[ec]] >= need:
            return v
    return None


def fingerprint(image_path):
    mat, version, modules, module_px, payload = extract_qr(image_path)
    ec, maskpat, _ = read_format_info(mat)
    func = function_modules(modules, version)
    # evaluate all 8 masks: unmask current first (XOR is its own inverse)
    base = apply_mask(mat, maskpat, func)
    scores = {}
    for m in range(8):
        scores[m] = penalty(apply_mask(base, m, func))
    best_mask = min(scores, key=scores.get)
    payload_len = len(payload.encode('utf-8'))
    mv = min_version(payload_len, ec) if ec in EC_IDX else None
    return {
        'image': os.path.basename(image_path),
        'payload': payload,
        'payload_len': payload_len,
        'version': version,
        'modules': modules,
        'ec_level': ec,
        'mask': maskpat,
        'mask_optimal': best_mask == maskpat,
        'best_mask': best_mask,
        'mask_scores': scores,
        'min_version_needed': mv,
        'oversize_versions': (version - mv) if mv else None,
        'module_px': round(float(module_px), 1),
    }


def compare(fp, ref):
    """Score similarity of a fingerprint against a reference (0-100)."""
    pts, why = 0, []
    checks = [
        ('version', 25, 'same QR version'),
        ('ec_level', 20, 'same error-correction level'),
        ('mask', 20, 'same mask pattern'),
        ('oversize_versions', 20, 'same version-overshoot behavior'),
        ('mask_optimal', 15, 'same mask-optimality behavior'),
    ]
    for key, w, label in checks:
        if fp.get(key) == ref.get(key) and fp.get(key) is not None:
            pts += w
            why.append(f'+{w} {label} ({fp.get(key)})')
        else:
            why.append(f'+0 {label} (this={fp.get(key)} ref={ref.get(key)})')
    return pts, why


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    img = sys.argv[1]
    fp = fingerprint(img)
    print(json.dumps(fp, indent=2))
    if '--save-ref' in sys.argv:
        name = sys.argv[sys.argv.index('--save-ref') + 1]
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'ref-{name}.json')
        with open(path, 'w') as f:
            json.dump(fp, f, indent=2)
        print(f'\nreference saved: {path}')
    if '--compare' in sys.argv:
        refpath = sys.argv[sys.argv.index('--compare') + 1]
        with open(refpath) as f:
            ref = json.load(f)
        score, why = compare(fp, ref)
        print(f'\nmatch score vs {os.path.basename(refpath)}: {score}/100')
        for line in why:
            print(' ', line)


if __name__ == '__main__':
    main()
