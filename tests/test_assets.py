import tempfile
import unittest
from pathlib import Path

from PIL import Image

from refind_forest.assets import ICON_NAMES, generate_theme


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UBUNTU_SOURCE = PROJECT_ROOT / "assets" / "source" / "ubuntu-logo.png"


class AssetTests(unittest.TestCase):
    def test_generator_uses_pillow_12_0_compatible_pixel_access(self) -> None:
        source = (PROJECT_ROOT / "src" / "refind_forest" / "assets.py").read_text()
        self.assertNotIn("get_flattened_data", source)

    def test_variants_generate_images_at_native_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for variant in ("a", "b"):
                with self.subTest(variant=variant):
                    target = root / f"forest-{variant}"
                    generate_theme(variant, target, UBUNTU_SOURCE)

                    expected_images = {
                        target / "background.png": ((2560, 1600), "RGB"),
                        target / "selection-big.png": ((144, 144), "RGBA"),
                        target / "selection-small.png": ((64, 64), "RGBA"),
                    }
                    for path, (size, mode) in expected_images.items():
                        with self.subTest(path=path.name):
                            with Image.open(path) as image:
                                self.assertEqual(image.size, size)
                                self.assertEqual(image.mode, mode)

                    for name, size in ICON_NAMES.items():
                        with self.subTest(icon=name):
                            with Image.open(target / "icons" / name) as image:
                                self.assertEqual(image.size, (size, size))
                                self.assertEqual(image.mode, "RGBA")
                                self.assertLess(image.getchannel("A").getextrema()[0], 255)

    def test_variants_have_distinct_ubuntu_icons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target_a = root / "forest-a"
            target_b = root / "forest-b"

            generate_theme("a", target_a, UBUNTU_SOURCE)
            generate_theme("b", target_b, UBUNTU_SOURCE)

            self.assertNotEqual(
                (target_a / "icons" / "os_ubuntu.png").read_bytes(),
                (target_b / "icons" / "os_ubuntu.png").read_bytes(),
            )

    def test_variants_have_distinct_selection_tiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target_a = root / "forest-a"
            target_b = root / "forest-b"
            generate_theme("a", target_a, UBUNTU_SOURCE)
            generate_theme("b", target_b, UBUNTU_SOURCE)

            for name in ("selection-big.png", "selection-small.png"):
                with self.subTest(name=name):
                    self.assertNotEqual(
                        (target_a / name).read_bytes(),
                        (target_b / name).read_bytes(),
                    )
                    with Image.open(target_a / name) as selection_a:
                        center_a = selection_a.getpixel(
                            (selection_a.width // 2, selection_a.height // 2)
                        )
                    with Image.open(target_b / name) as selection_b:
                        center_b = selection_b.getpixel(
                            (selection_b.width // 2, selection_b.height // 2)
                        )
                    self.assertGreater(sum(center_b[:3]), sum(center_a[:3]))
                    self.assertGreater(center_b[3], center_a[3])

    def test_invalid_variant_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-c"
            with self.assertRaisesRegex(ValueError, "variant must be 'a' or 'b'"):
                generate_theme("c", target, UBUNTU_SOURCE)

    def test_modified_ubuntu_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            modified_source = root / "ubuntu-logo.png"
            modified_source.write_bytes(b"not the vendored Ubuntu logo")

            with self.assertRaisesRegex(ValueError, "checksum"):
                generate_theme("a", root / "forest-a", modified_source)

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first"
            second = root / "second"

            generate_theme("a", first, UBUNTU_SOURCE)
            generate_theme("a", second, UBUNTU_SOURCE)

            first_files = {
                path.relative_to(first): path.read_bytes()
                for path in first.rglob("*.png")
            }
            second_files = {
                path.relative_to(second): path.read_bytes()
                for path in second.rglob("*.png")
            }
            self.assertEqual(first_files, second_files)

    def test_variant_b_linux_glyph_has_no_saturated_bright_colors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-b"
            generate_theme("b", target, UBUNTU_SOURCE)

            with Image.open(target / "icons" / "os_linux.png") as image:
                bright_pixels = []
                for count, (red, green, blue, alpha) in image.getcolors(
                    image.width * image.height
                ):
                    if alpha > 128 and max(red, green, blue) > 170:
                        bright_pixels.extend([(red, green, blue)] * count)

            self.assertTrue(bright_pixels)
            self.assertLessEqual(
                max(max(pixel) - min(pixel) for pixel in bright_pixels),
                40,
            )

    def test_ventoy_chevrons_have_a_dark_central_notch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-a"
            generate_theme("a", target, UBUNTU_SOURCE)

            with Image.open(target / "icons" / "os_ventoy.png") as image:
                red, green, blue, alpha = image.getpixel((64, 64))

            self.assertGreater(alpha, 128)
            self.assertLess(max(red, green, blue), 80)

    def test_windows_aliases_use_the_current_flat_mark(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-a"
            generate_theme("a", target, UBUNTU_SOURCE)

            self.assertEqual(
                (target / "icons" / "os_win.png").read_bytes(),
                (target / "icons" / "os_win8.png").read_bytes(),
            )

    def test_background_and_official_marks_use_expected_palette(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-a"
            generate_theme("a", target, UBUNTU_SOURCE)

            with Image.open(target / "background.png") as background:
                corner = background.getpixel((0, 0))
                self.assertTrue(all(channel < 40 for channel in corner))

            expected_colors = {
                "os_ubuntu.png": (233, 84, 32, 255),
                "os_win.png": (105, 182, 234, 255),
            }
            for name, expected_color in expected_colors.items():
                with self.subTest(name=name):
                    with Image.open(target / "icons" / name) as image:
                        colors = {
                            color: count
                            for count, color in image.getcolors(
                                image.width * image.height
                            )
                        }
                        transparent_pixels = image.getchannel("A").histogram()[0]
                        self.assertIn(expected_color, colors)
                        self.assertGreater(
                            transparent_pixels,
                            image.width * image.height // 2,
                        )

    def test_variant_b_official_marks_have_ice_glyphs_and_badges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "forest-b"
            generate_theme("b", target, UBUNTU_SOURCE)

            for name in ("os_ubuntu.png", "os_win.png"):
                with self.subTest(name=name):
                    with Image.open(target / "icons" / name) as image:
                        colors = image.getcolors(image.width * image.height)
                    color_counts = {color: count for count, color in colors}
                    badge_pixels = sum(
                        count
                        for count, (red, green, blue, alpha) in colors
                        if 150 <= alpha < 255
                        and max(red, green, blue) < 100
                        and green > red
                    )
                    self.assertIn((234, 244, 239, 255), color_counts)
                    self.assertGreater(badge_pixels, 1000)

    def test_every_icon_has_unclipped_transparent_exterior(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for variant in ("a", "b"):
                target = root / f"forest-{variant}"
                generate_theme(variant, target, UBUNTU_SOURCE)
                for name in ICON_NAMES:
                    with self.subTest(variant=variant, name=name):
                        with Image.open(target / "icons" / name) as image:
                            alpha = image.getchannel("A")
                            bounds = alpha.getbbox()
                            self.assertIsNotNone(bounds)
                            left, top, right, bottom = bounds
                            self.assertGreater(left, 0)
                            self.assertGreater(top, 0)
                            self.assertLess(right, image.width)
                            self.assertLess(bottom, image.height)
                            self.assertGreater(alpha.histogram()[0], image.width)

    def test_source_readme_records_yaru_license_and_attribution(self) -> None:
        readme = (PROJECT_ROOT / "assets" / "source" / "README.md").read_text()
        self.assertIn("https://github.com/ubuntu/yaru", readme)
        self.assertIn("Yaru contributors", readme)
        self.assertIn("Copyright: 2018, Sam Hewitt <sam@snwh.org>", readme)
        self.assertIn("CC BY-SA 4.0", readme)
        self.assertIn("https://creativecommons.org/licenses/by-sa/4.0/", readme)
        self.assertIn("derivatives remain under CC BY-SA 4.0", readme)


if __name__ == "__main__":
    unittest.main()
