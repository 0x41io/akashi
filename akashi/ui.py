"""Terminal styling for akashi: the banner."""

import shutil

from monomi.ui import paint, GREY, WHITE, BOLD
from akashi import __version__

# "akashi" in the BlurVision ASCII font (figlet), lightest shade removed and
# letters spaced out. Plain letters here, like Monomi's big logo; the styled
# ʌkʌshi is used in the one-line version below (as Monomi uses mønømi).
LOGO = [
    " ▒▓██████▓▒   ▒▓█▓▒  ▒▓█▓▒   ▒▓██████▓▒    ▒▓███████▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒         ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒         ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓████████▓▒  ▒▓███████▓▒   ▒▓████████▓▒   ▒▓██████▓▒   ▒▓████████▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒         ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒         ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓███████▓▒   ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
]
LOGO_WIDTH = max(len(row) for row in LOGO)


def banner() -> str:
    """The "akashi" wordmark with "by Øx41 · version" under its right edge.

    Narrow terminals get a one-line version so the big one never wraps.
    """
    tag_text = f"by Øx41 · v{__version__}"
    tag = (paint("by ", GREY) + paint("Øx41", BOLD, WHITE)
           + paint(f" · v{__version__}", GREY))

    cols = shutil.get_terminal_size((110, 24)).columns
    if cols <= LOGO_WIDTH:
        return f"\n{paint('ʌkʌshi', BOLD, WHITE)}  {tag}\n"

    logo = "\n".join(paint(row, WHITE) for row in LOGO)
    pad = " " * (LOGO_WIDTH - len(tag_text))
    return f"\n{logo}\n{pad}{tag}\n"
