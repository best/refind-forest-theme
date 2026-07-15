"""Build the fixed Forest A/B visual-inspection contact sheet."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUTPUT = Path("/tmp/refind-forest-contact-sheet.png")
THEMES = (("FOREST A", Path("/tmp/forest-a")), ("FOREST B", Path("/tmp/forest-b")))
ICONS = (
    ("Ubuntu", "os_ubuntu.png"),
    ("Windows", "os_win.png"),
    ("Ventoy", "os_ventoy.png"),
    ("UEFI", "os_uefi.png"),
    ("Unknown", "os_unknown.png"),
)
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def main() -> None:
    sheet = Image.new("RGB", (1400, 700), "#0B1013")
    draw = ImageDraw.Draw(sheet)
    label_font = ImageFont.truetype(FONT, 16)
    heading_font = ImageFont.truetype(FONT_BOLD, 18)

    for index, (heading, theme) in enumerate(THEMES):
        left = 40 + index * 680
        draw.text((left, 8), heading, font=heading_font, fill="#EAF4EF")
        with Image.open(theme / "background.png") as image:
            background = image.convert("RGB").resize((640, 400), Image.Resampling.LANCZOS)
        sheet.paste(background, (left, 34))

        for icon_index, (label, filename) in enumerate(ICONS):
            icon_left = left + 21 + icon_index * 122
            with Image.open(theme / "icons" / filename) as image:
                icon = image.convert("RGBA").resize((82, 82), Image.Resampling.LANCZOS)
            sheet.paste(icon, (icon_left, 468), icon)
            text_bounds = draw.textbbox((0, 0), label, font=label_font)
            text_width = text_bounds[2] - text_bounds[0]
            draw.text(
                (icon_left + (82 - text_width) / 2, 562),
                label,
                font=label_font,
                fill="#B9CCC5",
            )

    sheet.save(OUTPUT, format="PNG", optimize=True)


if __name__ == "__main__":
    main()
