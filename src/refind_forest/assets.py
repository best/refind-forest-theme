"""Generate deterministic raster assets for the Forest rEFInd themes."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont, ImageOps


ICON_NAMES: dict[str, int] = {
    "os_ubuntu.png": 128,
    "os_linux.png": 128,
    "os_win.png": 128,
    "os_win8.png": 128,
    "os_uefi.png": 128,
    "os_unknown.png": 128,
    "os_ventoy.png": 128,
    "func_firmware.png": 48,
    "func_reset.png": 48,
    "func_shutdown.png": 48,
    "tool_windows_rescue.png": 48,
    "vol_external.png": 32,
}

_UBUNTU_SOURCE_SHA256 = (
    "c28d4166e067916d6d8191fbb8283715e2d6554585a9d83ebd16c39c7b78d42a"
)
_DEJAVU_SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
_DEJAVU_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

_NEAR_BLACK = "#0d1318"
_DEEP_FOREST = "#20352f"
_ICE_WHITE = "#EAF4EF"
_UBUNTU_ORANGE = "#E95420"
_WINDOWS_BLUE = "#69B6EA"
_MUTED_TEAL = "#73A598"
_BADGE_GREEN = (16, 45, 38, 214)
_SCALE = 4


def _scale_box(box: tuple[float, float, float, float]) -> tuple[int, int, int, int]:
    return tuple(round(value * _SCALE) for value in box)  # type: ignore[return-value]


def _scale_points(points: list[tuple[float, float]]) -> list[tuple[int, int]]:
    return [(round(x * _SCALE), round(y * _SCALE)) for x, y in points]


def _finish_icon(image: Image.Image, size: int) -> Image.Image:
    return image.resize((size, size), Image.Resampling.LANCZOS)


def _build_background() -> Image.Image:
    size = (2560, 1600)
    horizontal = Image.linear_gradient("L").rotate(90, expand=True).resize(size)
    vertical = Image.linear_gradient("L").resize(size)
    diagonal = ImageChops.add(horizontal, vertical, scale=2.0)
    background = ImageOps.colorize(diagonal, black=_NEAR_BLACK, white=_DEEP_FOREST)

    band = Image.new("L", size, 0)
    band_draw = ImageDraw.Draw(band)
    band_draw.polygon(
        [(-620, -100), (-70, -100), (820, 1700), (220, 1700)],
        fill=70,
    )
    band = band.filter(ImageFilter.GaussianBlur(125))
    light = Image.new("RGB", size, "#7AA99A")
    background.paste(light, mask=band)

    draw = ImageDraw.Draw(background)
    title_font = ImageFont.truetype(_DEJAVU_BOLD, 62)
    subtitle_font = ImageFont.truetype(_DEJAVU_SANS, 21)
    draw.text((176, 128), "Flow Z13", font=title_font, fill=_ICE_WHITE)
    draw.text((180, 207), "BOOT SELECTOR", font=subtitle_font, fill="#9CB9AE")
    draw.rounded_rectangle((180, 248, 254, 253), radius=2, fill=_UBUNTU_ORANGE)
    return background.convert("RGB")


def _extract_ubuntu_mask(source: Path) -> Image.Image:
    with Image.open(source) as source_image:
        rgba = source_image.convert("RGBA")

    orange_rectangle = rgba.getchannel("A").getbbox()
    if orange_rectangle is None:
        raise ValueError("Ubuntu source does not contain the expected orange rectangle")
    inside = rgba.crop(orange_rectangle)
    rgba_bytes = inside.tobytes()
    mask_bytes = bytearray(inside.width * inside.height)
    for pixel_index, byte_index in enumerate(range(0, len(rgba_bytes), 4)):
        red, green, blue, alpha = rgba_bytes[byte_index : byte_index + 4]
        if red >= 235 and green >= 235 and blue >= 235:
            mask_bytes[pixel_index] = alpha
    mask = Image.frombytes("L", inside.size, bytes(mask_bytes))
    glyph_bounds = mask.getbbox()
    if glyph_bounds is None:
        raise ValueError("Ubuntu source does not contain a white Circle of Friends mask")
    return mask.crop(glyph_bounds)


def _badge(size: int) -> Image.Image:
    image = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    margin = size * 0.075
    draw.rounded_rectangle(
        _scale_box((margin, margin, size - margin, size - margin)),
        radius=round(size * 0.18 * _SCALE),
        fill=_BADGE_GREEN,
        outline=(119, 161, 148, 105),
        width=max(1, round(size * 0.012 * _SCALE)),
    )
    return image


def _icon_canvas(size: int, *, with_badge: bool) -> Image.Image:
    if with_badge:
        return _badge(size)
    return Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))


def _ubuntu_icon(variant: str, mask: Image.Image) -> Image.Image:
    size = 128
    canvas = _icon_canvas(size, with_badge=variant == "b")
    glyph_size = 88 if variant == "a" else 80
    resized_mask = mask.resize(
        (glyph_size * _SCALE, glyph_size * _SCALE),
        Image.Resampling.LANCZOS,
    )
    color = _UBUNTU_ORANGE if variant == "a" else _ICE_WHITE
    glyph = Image.new("RGBA", resized_mask.size, color)
    glyph.putalpha(resized_mask)
    offset = ((size - glyph_size) * _SCALE // 2,) * 2
    canvas.alpha_composite(glyph, offset)
    return _finish_icon(canvas, size)


def _draw_windows(variant: str) -> Image.Image:
    size = 128
    canvas = _icon_canvas(size, with_badge=variant == "b")
    draw = ImageDraw.Draw(canvas)
    color = _WINDOWS_BLUE if variant == "a" else _ICE_WHITE
    panes = [
        (27, 29, 60, 61),
        (67, 29, 101, 61),
        (27, 68, 60, 100),
        (67, 68, 101, 100),
    ]
    for pane in panes:
        draw.rounded_rectangle(
            _scale_box(pane),
            radius=2 * _SCALE,
            fill=color,
        )
    return _finish_icon(canvas, size)


def _draw_linux(variant: str) -> Image.Image:
    size = 128
    canvas = _icon_canvas(size, with_badge=True)
    draw = ImageDraw.Draw(canvas)
    color = _ICE_WHITE if variant == "b" else "#D7E7E0"
    dark = (18, 47, 40, 255)
    draw.ellipse(_scale_box((42, 25, 86, 70)), fill=color)
    draw.ellipse(_scale_box((34, 53, 94, 106)), fill=color)
    draw.ellipse(_scale_box((45, 65, 83, 103)), fill=dark)
    draw.ellipse(_scale_box((51, 42, 58, 51)), fill=dark)
    draw.ellipse(_scale_box((70, 42, 77, 51)), fill=dark)
    accent = "#C6A864" if variant == "a" else "#B8CCC4"
    draw.polygon(_scale_points([(58, 53), (70, 53), (64, 61)]), fill=accent)
    draw.ellipse(_scale_box((28, 94, 60, 105)), fill=accent)
    draw.ellipse(_scale_box((68, 94, 100, 105)), fill=accent)
    return _finish_icon(canvas, size)


def _draw_usb(variant: str, *, unknown: bool) -> Image.Image:
    size = 128
    canvas = _icon_canvas(size, with_badge=True)
    draw = ImageDraw.Draw(canvas)
    color = _ICE_WHITE if variant == "b" else "#CFE2DA"
    dark = (17, 48, 40, 255)
    draw.rounded_rectangle(
        _scale_box((25, 43, 79, 88)),
        radius=10 * _SCALE,
        fill=color,
    )
    draw.rectangle(_scale_box((75, 51, 103, 80)), fill=color)
    draw.rectangle(_scale_box((101, 56, 108, 75)), fill=color)
    draw.rounded_rectangle(_scale_box((84, 56, 91, 64)), radius=2 * _SCALE, fill=dark)
    draw.rounded_rectangle(_scale_box((84, 68, 91, 76)), radius=2 * _SCALE, fill=dark)
    if unknown:
        font = ImageFont.truetype(_DEJAVU_BOLD, 30 * _SCALE)
        draw.text(
            (52 * _SCALE, 64 * _SCALE),
            "?",
            font=font,
            fill=dark,
            anchor="mm",
            stroke_width=0,
        )
    else:
        width = 4 * _SCALE
        draw.line(
            _scale_points([(38, 66), (48, 56), (59, 66), (68, 56)]),
            fill=dark,
            width=width,
            joint="curve",
        )
        draw.ellipse(_scale_box((35, 63, 41, 69)), fill=dark)
        draw.rectangle(_scale_box((65, 53, 71, 59)), fill=dark)
    return _finish_icon(canvas, size)


def _draw_ventoy(variant: str) -> Image.Image:
    size = 128
    canvas = _icon_canvas(size, with_badge=True)
    draw = ImageDraw.Draw(canvas)
    color = _ICE_WHITE if variant == "b" else "#BFD8CE"
    width = 12 * _SCALE
    draw.line(
        _scale_points([(27, 33), (55, 64), (27, 95)]),
        fill=color,
        width=width,
        joint="curve",
    )
    draw.line(
        _scale_points([(101, 33), (73, 64), (101, 95)]),
        fill=color,
        width=width,
        joint="curve",
    )
    draw.polygon(
        _scale_points([(64, 54), (71, 64), (64, 74), (57, 64)]),
        fill=(17, 48, 40, 255),
    )
    return _finish_icon(canvas, size)


def _draw_external() -> Image.Image:
    size = 32
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle(
        _scale_box((4, 9, 19, 24)),
        radius=4 * _SCALE,
        fill=_ICE_WHITE,
    )
    draw.rectangle(_scale_box((17, 12, 26, 21)), fill=_ICE_WHITE)
    draw.rectangle(_scale_box((24, 14, 28, 19)), fill=_ICE_WHITE)
    draw.rectangle(_scale_box((20, 13, 23, 16)), fill=_DEEP_FOREST)
    draw.rectangle(_scale_box((20, 18, 23, 20)), fill=_DEEP_FOREST)
    draw.ellipse(_scale_box((9, 14, 14, 19)), fill=_MUTED_TEAL)
    return _finish_icon(canvas, size)


def _gear_icon() -> Image.Image:
    size = 48
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    points = []
    for index in range(24):
        angle = -math.pi / 2 + index * math.pi / 12
        radius = (20, 16, 17)[index % 3]
        points.append((24 + radius * math.cos(angle), 24 + radius * math.sin(angle)))
    draw.polygon(_scale_points(points), fill=_ICE_WHITE)
    draw.ellipse(_scale_box((15, 15, 33, 33)), fill=(0, 0, 0, 0))
    draw.ellipse(_scale_box((20, 20, 28, 28)), fill=_ICE_WHITE)
    return _finish_icon(canvas, size)


def _reset_icon() -> Image.Image:
    size = 48
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.arc(
        _scale_box((7, 7, 41, 41)),
        start=-62,
        end=247,
        fill=_ICE_WHITE,
        width=5 * _SCALE,
    )
    draw.polygon(
        _scale_points([(34, 5), (44, 8), (39, 18)]),
        fill=_ICE_WHITE,
    )
    return _finish_icon(canvas, size)


def _shutdown_icon() -> Image.Image:
    size = 48
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.arc(
        _scale_box((7, 8, 41, 42)),
        start=-48,
        end=228,
        fill=_ICE_WHITE,
        width=5 * _SCALE,
    )
    draw.line(
        _scale_points([(24, 5), (24, 25)]),
        fill=_ICE_WHITE,
        width=5 * _SCALE,
    )
    return _finish_icon(canvas, size)


def _windows_recovery_icon() -> Image.Image:
    size = 48
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    for box in ((7, 7, 20, 19), (24, 7, 37, 19), (7, 23, 20, 35), (24, 23, 37, 35)):
        draw.rectangle(_scale_box(box), fill=_ICE_WHITE)
    draw.arc(
        _scale_box((19, 18, 45, 44)),
        start=20,
        end=260,
        fill=_MUTED_TEAL,
        width=4 * _SCALE,
    )
    draw.polygon(
        _scale_points([(18, 38), (28, 38), (23, 29)]),
        fill=_MUTED_TEAL,
    )
    return _finish_icon(canvas, size)


def _selection(variant: str, size: int) -> Image.Image:
    canvas = Image.new("RGBA", (size * _SCALE, size * _SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    margin = max(5, round(size * 0.07))
    radius = round(size * 0.15 * _SCALE)
    if variant == "a":
        shadow_offset = max(1, round(size * 0.014))
        draw.rounded_rectangle(
            _scale_box(
                (
                    margin + shadow_offset,
                    margin + shadow_offset,
                    size - margin + shadow_offset,
                    size - margin + shadow_offset,
                )
            ),
            radius=radius,
            fill=(3, 12, 10, 34),
        )
        fill = (43, 78, 69, 68)
        outline = (104, 150, 139, 185)
    else:
        fill = (92, 139, 123, 106)
        outline = (171, 216, 201, 228)
    draw.rounded_rectangle(
        _scale_box((margin, margin, size - margin, size - margin)),
        radius=radius,
        fill=fill,
        outline=outline,
        width=max(1, round(size * 0.022 * _SCALE)),
    )
    return _finish_icon(canvas, size)


def _build_icons(variant: str, ubuntu_mask: Image.Image) -> dict[str, Image.Image]:
    builders: dict[str, Callable[[], Image.Image]] = {
        "os_ubuntu.png": lambda: _ubuntu_icon(variant, ubuntu_mask),
        "os_linux.png": lambda: _draw_linux(variant),
        "os_win.png": lambda: _draw_windows(variant),
        "os_win8.png": lambda: _draw_windows(variant),
        "os_uefi.png": lambda: _draw_usb(variant, unknown=False),
        "os_unknown.png": lambda: _draw_usb(variant, unknown=True),
        "os_ventoy.png": lambda: _draw_ventoy(variant),
        "func_firmware.png": _gear_icon,
        "func_reset.png": _reset_icon,
        "func_shutdown.png": _shutdown_icon,
        "tool_windows_rescue.png": _windows_recovery_icon,
        "vol_external.png": _draw_external,
    }
    return {name: builders[name]() for name in ICON_NAMES}


def generate_theme(variant: str, target: Path, ubuntu_source: Path) -> None:
    """Generate one complete Forest theme in a fresh target directory."""
    if variant not in {"a", "b"}:
        raise ValueError("variant must be 'a' or 'b'")

    ubuntu_source = Path(ubuntu_source)
    checksum = hashlib.sha256(ubuntu_source.read_bytes()).hexdigest()
    if checksum != _UBUNTU_SOURCE_SHA256:
        raise ValueError(
            "Ubuntu source checksum mismatch: "
            f"expected {_UBUNTU_SOURCE_SHA256}, got {checksum}"
        )

    ubuntu_mask = _extract_ubuntu_mask(ubuntu_source)
    background = _build_background()
    icons = _build_icons(variant, ubuntu_mask)

    target = Path(target)
    target.mkdir(parents=True, exist_ok=False)
    icon_directory = target / "icons"
    icon_directory.mkdir()

    background.save(target / "background.png", format="PNG", optimize=True)
    _selection(variant, 144).save(
        target / "selection-big.png", format="PNG", optimize=True
    )
    _selection(variant, 64).save(
        target / "selection-small.png", format="PNG", optimize=True
    )
    for name, image in icons.items():
        image.save(icon_directory / name, format="PNG", optimize=True)
