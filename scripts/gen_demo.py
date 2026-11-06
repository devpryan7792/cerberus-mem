#!/usr/bin/env python3
"""Generate assets/demo.svg with exactly aligned terminal columns."""

from pathlib import Path

FS = 13.0
ADV = FS * 0.6  # monospace advance width

W, H = 1240, 452
OUT = Path(__file__).resolve().parents[1] / "assets" / "demo.svg"

C_BG1, C_BG2 = "#0b0f16", "#070a10"
C_BAR1, C_BAR2 = "#101722", "#0c121b"
C_PROMPT = "#4a7fd0"
C_TEXT = "#e2e8f0"
C_DIM = "#94a3b8"
C_DESC = "#cbd5e1"
C_CRIT = "#d0574f"
C_HIGH = "#d0574f"
C_MED = "#d9a441"
C_OK = "#4a9d6f"
C_FAINT = "#475569"
C_EDGE = "#1e2b3d"
C_RULE = "#16202e"

# column origins (px)
X = 26
X_SEVERITY = X
X_PID = X_SEVERITY + 11 * ADV
X_TYPE = X_PID + 12 * ADV
X_DESC = X_TYPE + 28 * ADV


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def row(y, severity, color, pid, kind, desc):
    parts = [
        f'<text x="{X_SEVERITY:.1f}" y="{y}" fill="{color}">{esc(severity)}</text>',
        f'<text x="{X_PID:.1f}" y="{y}" fill="{C_DIM}">{esc(pid)}</text>',
        f'<text x="{X_TYPE:.1f}" y="{y}" fill="{C_DIM}">{esc(kind)}</text>',
    ]
    if desc:
        parts.append(
            f'<text x="{X_DESC:.1f}" y="{y}" fill="{C_DESC}">{esc(desc)}</text>'
        )
    return "    " + "\n    ".join(parts)


lines = []
lines.append(
    '<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="452" viewBox="0 0 1240 452" role="img" aria-label="cerberus-mem scanning a live host and detecting a synthetic in-memory payload">'
)
lines.append("  <defs>")
lines.append('    <linearGradient id="win" x1="0" y1="0" x2="0" y2="1">')
lines.append(f'      <stop offset="0" stop-color="{C_BG1}"/>')
lines.append(f'      <stop offset="1" stop-color="{C_BG2}"/>')
lines.append("    </linearGradient>")
lines.append('    <linearGradient id="bar" x1="0" y1="0" x2="1" y2="0">')
lines.append(f'      <stop offset="0" stop-color="{C_BAR1}"/>')
lines.append(f'      <stop offset="1" stop-color="{C_BAR2}"/>')
lines.append("    </linearGradient>")
lines.append("  </defs>")
lines.append("")
lines.append(
    f'  <rect width="{W}" height="{H}" rx="12" fill="url(#win)" stroke="{C_EDGE}"/>'
)
lines.append(
    f'  <path d="M0 12 A12 12 0 0 1 12 0 H1228 A12 12 0 0 1 1240 12 V44 H0 Z" fill="url(#bar)"/>'
)
lines.append(f'  <line x1="0" y1="44" x2="{W}" y2="44" stroke="{C_EDGE}"/>')
lines.append("")
lines.append(f'  <circle cx="22" cy="22" r="5.5" fill="#ff5f57"/>')
lines.append(f'  <circle cx="41" cy="22" r="5.5" fill="#febc2e"/>')
lines.append(f'  <circle cx="60" cy="22" r="5.5" fill="#28c840"/>')
lines.append(
    f'  <text x="{W / 2:.0f}" y="27" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="11.5" fill="#64748b">cerberus-mem — live host sweep</text>'
)
lines.append("")
lines.append(
    f'  <g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="{FS}" xml:space="preserve">'
)
lines.append(f'    <text x="{X}" y="82" fill="{C_PROMPT}">$</text>')
lines.append(
    f'    <text x="{X + 2 * ADV:.1f}" y="82" fill="{C_TEXT}">cerberus-mem --all</text>'
)
lines.append("")
lines.append(
    row(
        114,
        "[High]",
        C_HIGH,
        "pid=1631",
        "WxorXViolation",
        "Mapping 0x7f0401a2e000-0x7f0401a3e000 is writable and executable",
    )
)
lines.append(
    row(
        138,
        "[Medium]",
        C_MED,
        "pid=1631",
        "AnonymousExecutableMapping",
        "Executable anonymous mapping, 65536 bytes",
    )
)
lines.append(
    row(
        162,
        "[High]",
        C_HIGH,
        "pid=2088",
        "WxorXViolation",
        "Mapping 0x3ab0a6529000-0x3ab0a6539000 is writable and executable",
    )
)
lines.append(
    row(
        186,
        "[Critical]",
        C_CRIT,
        "pid=169271",
        "AnonymousExecutableMapping",
        "Executable anonymous mapping, 2117632 bytes exceeds 64 KiB threshold",
    )
)
lines.append("")
lines.append(f'    <text x="{X}" y="212" fill="{C_FAINT}">...</text>')
lines.append(
    f'    <text x="{X}" y="240" fill="{C_OK}">cerberus-mem: 127 finding(s)</text>'
)
lines.append("  </g>")
lines.append("")
lines.append(f'  <line x1="{X}" y1="260" x2="{W - 26}" y2="260" stroke="{C_RULE}"/>')
lines.append("")
lines.append(
    f'  <g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="{FS}" xml:space="preserve">'
)
lines.append(f'    <text x="{X}" y="292" fill="{C_PROMPT}">$</text>')
lines.append(
    f'    <text x="{X + 2 * ADV:.1f}" y="292" fill="{C_TEXT}">cerberus-mem --pid 196815</text>'
)
lines.append(
    f'    <text x="{X + 28 * ADV:.1f}" y="292" fill="{C_FAINT}"># synthetic memfd payload</text>'
)
lines.append("")
lines.append(
    row(
        324,
        "[Critical]",
        C_CRIT,
        "pid=196815",
        "FilelessMemfdExecution",
        "Executable is backed by anonymous memory fd: /memfd:payload (deleted)",
    )
)
lines.append(
    row(
        348,
        "[Critical]",
        C_CRIT,
        "pid=197412",
        "ProcessHollowing",
        "Live .text diverges from on-disk image: 16 byte(s) differ, first at offset 0x0",
    )
)
lines.append(
    f'    <text x="{X}" y="372" fill="{C_OK}">cerberus-mem: 2 finding(s)</text>'
)
lines.append("  </g>")
lines.append("")
lines.append(f'  <line x1="{X}" y1="394" x2="{W - 26}" y2="394" stroke="{C_RULE}"/>')
lines.append(
    f'  <text x="{X}" y="418" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="11" fill="#475569">process_vm_readv(2) · /proc/[pid]/mem fallback · relocation-masked SHA-256 · JSON-Lines · quarantine with O_NOFOLLOW</text>'
)
lines.append(
    f'  <text x="{X}" y="438" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="11" fill="#334155">Output shown verbatim from a live run.</text>'
)
lines.append("</svg>")

OUT.write_text("\n".join(lines) + "\n")
print(f"wrote {OUT}")
