"""
banner.py — Animated Hashtrace launch banner.

Features:
  1. Gradient-colored FIGlet ASCII art  (red → orange tones)
  2. Line-by-line typing reveal animation
  3. Subtle thin-line frame
  4. Tagline + version pill

Uses only Rich — zero extra dependencies.
"""

import sys
import time

# Force UTF-8 output on Windows to support box-drawing characters.
# This must happen before any Rich output.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.text import Text


# ── Constants ────────────────────────────────────────────────────────────────

VERSION = "v3.0"

FIGLET_LINES = [
    "██╗  ██╗ █████╗ ███████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗",
    "██║  ██║██╔══██╗██╔════╝██║  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝",
    "███████║███████║███████╗███████║   ██║   ██████╔╝███████║██║     █████╗  ",
    "██╔══██║██╔══██║╚════██║██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ",
    "██║  ██║██║  ██║███████║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗",
    "╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝",
]

SUBTITLE = "Trace Every Hash. Trust No Password."

# Wide gradient (red → yellow → cyan)
GRADIENT_COLORS = [
    "#ff0040",  # hot red
    "#ff2040",
    "#ff4030",
    "#ff6020",
    "#ff8010",
    "#ffa000",
    "#ffc000",
    "#ffe000",
    "#e0ff00",
    "#a0ff40",
    "#60ff80",
    "#30ffa0",
    "#00ffc0",
    "#00ffe0",
    "#00e0ff",
    "#00c0ff",
    "#00a0ff",
]

# Frame width matches the widest ANSI Shadow line
FRAME_INNER_WIDTH = 73


# ── Helpers ──────────────────────────────────────────────────────────────────

def _color_for_position(index: int, total: int) -> str:
    """Pick a gradient color based on horizontal position."""
    if total <= 1:
        return GRADIENT_COLORS[0]
    ratio = index / (total - 1)
    color_index = int(ratio * (len(GRADIENT_COLORS) - 1))
    return GRADIENT_COLORS[min(color_index, len(GRADIENT_COLORS) - 1)]


def _gradient_line(line: str) -> Text:
    """Apply a horizontal gradient across a single line of text."""
    text = Text()
    total = len(line)
    for i, ch in enumerate(line):
        color = _color_for_position(i, total)
        text.append(ch, style=f"bold {color}")
    return text


def _build_gradient_art() -> list[Text]:
    """Convert FIGLET_LINES into gradient-colored Rich Text objects."""
    return [_gradient_line(line) for line in FIGLET_LINES]


def _pad_text(text: Text, target_width: int) -> Text:
    """Pad a Rich Text object to a target width with trailing spaces."""
    padded = Text()
    padded.append(text)
    plain_len = len(text.plain)
    if plain_len < target_width:
        padded.append(" " * (target_width - plain_len))
    return padded


def _center_str(content: str, width: int) -> tuple[int, int]:
    """Return (left_pad, right_pad) to center content in width."""
    pad_left = (width - len(content)) // 2
    pad_right = width - len(content) - pad_left
    return pad_left, pad_right


def _build_frame(content_lines: list[Text], subtitle: Text, version_pill: Text) -> Text:
    """Wrap content in a subtle thin-line frame."""
    w = FRAME_INNER_WIDTH
    frame = Text()

    # ── Top border ──
    frame.append("  ╭", style="dim #444444")
    frame.append("─" * (w + 2), style="dim #444444")
    frame.append("╮\n", style="dim #444444")

    # ── Top padding ──
    frame.append("  │", style="dim #444444")
    frame.append(" " * (w + 2))
    frame.append("│\n", style="dim #444444")

    # ── FIGlet content lines ──
    for line in content_lines:
        frame.append("  │", style="dim #444444")
        frame.append(" ", style="")
        padded = _pad_text(line, w)
        frame.append(padded)
        frame.append(" ", style="")
        frame.append("│\n", style="dim #444444")

    # ── Spacer after art ──
    frame.append("  │", style="dim #444444")
    frame.append(" " * (w + 2))
    frame.append("│\n", style="dim #444444")

    # ── Subtitle + version row ──
    frame.append("  │", style="dim #444444")
    frame.append(" ", style="")
    sub_version = Text()
    sub_str = subtitle.plain
    ver_display = VERSION
    combined = sub_str + "  " + ver_display
    pad_l, pad_r = _center_str(combined, w)
    sub_version.append(" " * pad_l)
    sub_version.append(subtitle)
    sub_version.append("  ", style="")
    sub_version.append(ver_display, style="dim #666666")
    sub_version.append(" " * pad_r)
    frame.append(sub_version)
    frame.append(" ", style="")
    frame.append("│\n", style="dim #444444")

    # ── Bottom padding ──
    frame.append("  │", style="dim #444444")
    frame.append(" " * (w + 2))
    frame.append("│\n", style="dim #444444")

    # ── Bottom border ──
    frame.append("  ╰", style="dim #444444")
    frame.append("─" * (w + 2), style="dim #444444")
    frame.append("╯", style="dim #444444")

    return frame


# ── Public API ───────────────────────────────────────────────────────────────

def print_banner(console: Console, animate: bool = True) -> None:
    """
    Render the Hashtrace launch banner to *console*.

    If *animate* is True (default), plays a line-by-line reveal animation.
    If False, prints the static frame immediately (useful for piped output).
    """
    subtitle = Text(SUBTITLE, style="dim italic #888888")
    version_pill = Text(VERSION, style="dim #666666")

    # Skip animation if output is not a real terminal
    if not console.is_terminal:
        animate = False

    if animate:
        _play_line_reveal(console, subtitle, version_pill)
    else:
        gradient_lines = _build_gradient_art()
        final_frame = _build_frame(gradient_lines, subtitle, version_pill)
        console.print()
        console.print(final_frame)
        console.print()


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Convert '#RRGGBB' to (R, G, B) tuple."""
    return (
        int(hex_color[1:3], 16),
        int(hex_color[3:5], 16),
        int(hex_color[5:7], 16),
    )


# Pre-computed ANSI sequences
_BR, _BG, _BB = _hex_to_rgb("#444444")
_ANSI_BORDER = f"\033[2;38;2;{_BR};{_BG};{_BB}m"
_ANSI_RESET = "\033[0m"
_ANSI_DIM_SUB = "\033[2;3;38;2;136;136;136m"   # dim italic #888888
_ANSI_DIM_VER = "\033[2;38;2;102;102;102m"      # dim #666666


def _play_line_reveal(
    console: Console,
    subtitle: Text,
    version_pill: Text,
) -> None:
    """Character-by-character typing animation using direct ANSI output."""

    char_delay = 0.003   # seconds per visible character (spaces are instant)
    w = FRAME_INNER_WIDTH
    out = sys.stdout
    b = _ANSI_BORDER
    r = _ANSI_RESET

    out.write("\n")

    # Top border (instant)
    out.write(f"  {b}\u256d{'\u2500' * (w + 2)}\u256e{r}\n")

    # Top padding (instant)
    out.write(f"  {b}\u2502{r}{' ' * (w + 2)}{b}\u2502{r}\n")
    out.flush()

    # Art lines — type each character one by one
    for original_line in FIGLET_LINES:
        # Left border (instant)
        out.write(f"  {b}\u2502{r} ")
        out.flush()

        total = len(original_line)
        for i, ch in enumerate(original_line):
            if ch == " ":
                out.write(" ")
            else:
                color = _color_for_position(i, total)
                cr, cg, cb = _hex_to_rgb(color)
                out.write(f"\033[1;38;2;{cr};{cg};{cb}m{ch}{r}")
                out.flush()
                time.sleep(char_delay)

        # Pad remaining width + right border
        remaining = w - len(original_line)
        if remaining > 0:
            out.write(" " * remaining)
        out.write(f" {b}\u2502{r}\n")
        out.flush()

    # Spacer (instant)
    out.write(f"  {b}\u2502{r}{' ' * (w + 2)}{b}\u2502{r}\n")

    # Subtitle + version row (instant)
    sub_str = SUBTITLE
    ver_str = VERSION
    combined = sub_str + "  " + ver_str
    pad_l = (w - len(combined)) // 2
    pad_r = w - len(combined) - pad_l
    out.write(
        f"  {b}\u2502{r} "
        f"{' ' * pad_l}"
        f"{_ANSI_DIM_SUB}{sub_str}{r}"
        f"  "
        f"{_ANSI_DIM_VER}{ver_str}{r}"
        f"{' ' * pad_r}"
        f" {b}\u2502{r}\n"
    )

    # Bottom padding (instant)
    out.write(f"  {b}\u2502{r}{' ' * (w + 2)}{b}\u2502{r}\n")

    # Bottom border (instant)
    out.write(f"  {b}\u2570{'\u2500' * (w + 2)}\u256f{r}\n")

    out.write("\n")
    out.flush()
