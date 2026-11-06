#!/usr/bin/env python3
"""Generate assets/banner.svg.

A Kangwa wave crest carrying the wordmark. Restrained palette: two muted
taegeuk hues on near-black, one hairline accent. No gradients on text, no
glow filters, no badges.
"""

import math
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "assets" / "banner.svg"

W, H = 1400, 380

BG = "#0a0a0f"
BLUE = "#4a7fd0"
RED = "#d0574f"
INK = "#f0f0f4"
KICKER = "#75758a"
SUB = "#a4a4b4"
CAPS = "#63637a"
HAIR = "#23232e"

# wave geometry: crests at CREST_X, troughs midway between them
WAVELEN = 280.0
CREST_X = [140.0, 420.0, 700.0, 980.0, 1260.0]
CREST_Y = 104.0
TROUGH_Y = 150.0
MID_Y = (CREST_Y + TROUGH_Y) / 2.0
AMP = (TROUGH_Y - CREST_Y) / 2.0

PERIOD = WAVELEN
START_CREST = 140.0  # x of the first crest; x=0 is a trough


def wave_y(x):
    """Sine wave value at x."""
    return MID_Y - AMP * math.cos(2 * math.pi * (x - START_CREST) / PERIOD)


def wave_path(x_from, x_to):
    """Smooth path through the wave's crests and troughs over [x_from, x_to]."""
    # Extrema sit at half-period intervals.
    points = []
    x = 0.0
    while x <= W:
        points.append((x, wave_y(x)))
        x += PERIOD / 2

    span = [p for p in points if x_from - 1e-6 <= p[0] <= x_to + 1e-6]
    if not span or span[0][0] > x_from:
        span.insert(0, (x_from, wave_y(x_from)))
    if span[-1][0] < x_to:
        span.append((x_to, wave_y(x_to)))

    d = [f"M {span[0][0]:.2f} {span[0][1]:.2f}"]
    for (x0, y0), (x1, y1) in zip(span, span[1:]):
        dx = x1 - x0
        # Horizontal tangents at the extrema give a smooth, sine-like curve.
        d.append(
            f"C {x0 + dx * 0.30:.2f} {y0:.2f} {x1 - dx * 0.30:.2f} {y1:.2f} "
            f"{x1:.2f} {y1:.2f}"
        )
    return " ".join(d)


def figure(cx, color, flip):
    """A small figure standing on a crest with one arm raised."""
    direction = -1 if flip else 1
    head_y = CREST_Y - 36
    return f"""    <g stroke="{color}" fill="{color}" stroke-linecap="round">
      <circle cx="{cx}" cy="{head_y}" r="7.5" stroke="none"/>
      <path d="M {cx} {head_y + 9} L {cx} {CREST_Y - 2}" stroke-width="7" fill="none"/>
      <path d="M {cx + 2 * direction} {head_y + 17} L {cx + 14 * direction} {head_y + 2}" stroke-width="4" fill="none"/>
      <path d="M {cx - 2 * direction} {head_y + 20} L {cx - 11 * direction} {head_y + 10}" stroke-width="4" fill="none"/>
    </g>"""


parts = []
parts.append(
    '<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="380" viewBox="0 0 1400 380" role="img" aria-label="Cerberus-Mem — Linux in-memory forensics">'
)
parts.append("  <defs>")
parts.append('    <linearGradient id="rule" x1="0" y1="0" x2="1" y2="0">')
parts.append(f'      <stop offset="0" stop-color="{BLUE}"/>')
parts.append(f'      <stop offset="1" stop-color="{RED}"/>')
parts.append("    </linearGradient>")
parts.append("  </defs>")
parts.append("")
parts.append(f'  <rect width="{W}" height="{H}" fill="{BG}"/>')
parts.append("")

# the wave: two hues meeting at the centre crest
parts.append('  <g fill="none" stroke-linecap="round">')
parts.append(f'    <path d="{wave_path(0, 700)}" stroke="{BLUE}" stroke-width="7"/>')
parts.append(f'    <path d="{wave_path(700, W)}" stroke="{RED}" stroke-width="7"/>')
parts.append("  </g>")
parts.append("")

# a faint echo below adds depth without noise
parts.append('  <g fill="none" stroke-linecap="round" opacity="0.16">')
parts.append(
    f'    <path d="{wave_path(0, 700)}" stroke="{BLUE}" stroke-width="2" transform="translate(0 30)"/>'
)
parts.append(
    f'    <path d="{wave_path(700, W)}" stroke="{RED}" stroke-width="2" transform="translate(0 30)"/>'
)
parts.append("  </g>")
parts.append("")

# break in the wave for the taegeuk
parts.append(f'  <circle cx="700" cy="{CREST_Y}" r="29" fill="{BG}"/>')
parts.append(f'  <circle cx="700" cy="{CREST_Y}" r="21" fill="{BLUE}"/>')
parts.append(
    f'  <path d="M 700 {CREST_Y - 21} A 21 21 0 0 1 700 {CREST_Y + 21} '
    f'A 10.5 10.5 0 0 1 700 {CREST_Y} A 10.5 10.5 0 0 0 700 {CREST_Y - 21} Z" fill="{RED}"/>'
)
parts.append("")

# figures waving along the crests
parts.append("  <g>")
for i, cx in enumerate([c for c in CREST_X if c != 700.0]):
    color = BLUE if cx < 700 else RED
    parts.append(figure(cx, color, flip=(i % 2 == 1)))
parts.append("  </g>")
parts.append("")

# typography
parts.append(
    f'  <text x="700" y="200" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="12" letter-spacing="6.5" fill="{KICKER}">LINUX · IN-MEMORY · FORENSICS</text>'
)
parts.append(
    f'  <text x="700" y="258" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="62" font-weight="700" letter-spacing="7" fill="{INK}">CERBERUS-MEM</text>'
)
parts.append(
    f'  <line x1="432" y1="278" x2="968" y2="278" stroke="url(#rule)" stroke-width="2"/>'
)
parts.append(
    f'  <text x="700" y="308" text-anchor="middle" font-family="Inter, \'Segoe UI\', Helvetica, Arial, sans-serif" font-size="19" fill="{SUB}">Find the code that only exists in memory.</text>'
)
parts.append("")
parts.append(
    f'  <text x="700" y="342" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="11.5" letter-spacing="1.6" fill="{CAPS}">FILELESS · HOLLOWING · GOT/PLT · INLINE HOOKS · W^X · PASSIVE</text>'
)
parts.append(
    f'  <line x1="432" y1="360" x2="968" y2="360" stroke="{HAIR}" stroke-width="1"/>'
)
parts.append("</svg>")

OUT.write_text("\n".join(parts) + "\n")
print(f"wrote {OUT}")
