"""Render the app and tray icons from SVG: python3 desktop/icons/make_icons.py (needs ImageMagick).

The app icon is the dashboard's chamfered panel with a neon eye; the tray icon is the eye alone,
coloured by state with the dashboard's own severity colours. The PNGs are committed; run this
only to change them."""

import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CYAN, MAGENTA, BG, LINE = "#00f0ff", "#ff2bd6", "#06050b", "#3a3062"
TRAY = {"quiet": "#3dff9a", "watch": "#00f0ff", "warn": "#f3ff4a", "critical": "#ff3864",
        "stale": "#8f88b3", "down": "#5c5580"}


def eye(colour: str, pupil: str, stroke: float) -> str:
    return (f'<path d="M 8 32 Q 32 8 56 32 Q 32 56 8 32 Z" fill="none" stroke="{colour}" '
            f'stroke-width="{stroke}" stroke-linejoin="round"/>'
            f'<circle cx="32" cy="32" r="8.5" fill="{pupil}"/>'
            f'<circle cx="35" cy="29" r="2.4" fill="{BG}"/>')


def app_svg() -> str:
    panel = "M 6 2 H 50 L 62 14 V 58 Q 62 62 58 62 H 14 L 2 50 V 6 Q 2 2 6 2 Z"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
            f'<path d="{panel}" fill="{BG}" stroke="{LINE}" stroke-width="2"/>'
            f'<g transform="translate(32 33) scale(.78) translate(-32 -32)">'
            f'{eye(CYAN, MAGENTA, 4.5)}</g></svg>')


def tray_svg(state: str) -> str:
    colour = TRAY[state]
    slash = (f'<path d="M 12 54 L 52 10" stroke="{colour}" stroke-width="5" '
             f'stroke-linecap="round"/>' if state == "down" else "")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
            f'{eye(colour, colour, 6)}{slash}</svg>')


def render(svg: str, size: int, out: pathlib.Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".svg") as src:
        src.write(svg)
        src.flush()
        # -strip and no tIME chunk: the files carry no metadata, not even when they were made.
        subprocess.run(["convert", "-background", "none", "-density", str(size * 6), src.name,
                        "-strip", "-define", "png:exclude-chunks=date,time",
                        "-resize", f"{size}x{size}", f"PNG32:{out}"], check=True)


if __name__ == "__main__":
    for size, name in ((32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png"),
                       (512, "icon.png")):
        render(app_svg(), size, HERE / name)
    (HERE / "neonwatch.svg").write_text(app_svg() + "\n")
    for state in TRAY:
        render(tray_svg(state), 64, HERE / f"tray-{state}.png")
