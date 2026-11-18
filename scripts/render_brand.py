"""Rasteriza los caracteres y colores del retrato para el splash de Swing."""
from pathlib import Path
from xml.etree import ElementTree
import argparse
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("mono", help="Ruta de la tipografía Courier New")
parser.add_argument("serif", help="Ruta de la tipografía Georgia")
args = parser.parse_args()
svg = ElementTree.parse(ROOT / "assets/mascara.svg").getroot()
scale = 4
portrait = Image.new("RGB", (650 * scale, 780 * scale), "#080807")
ink = ImageDraw.Draw(portrait)
group = svg.find("{*}g")
mono = ImageFont.truetype(args.mono, round(float(group.get("font-size")) * scale))
for line in group:
    y = float(line.get("y")) * scale
    for span in line:
        chars = span.text or ""
        x = float(span.get("x")) * scale
        step = float(span.get("textLength")) * scale / max(1, len(chars))
        for column, char in enumerate(chars):
            ink.text((x + step * column, y), char, font=mono, fill=span.get("fill"), anchor="ls")

cover = Image.new("RGB", (1000, 1000), "#080807")
cover.paste(portrait.resize((660, 792), Image.Resampling.LANCZOS), (170, 16))
ink = ImageDraw.Draw(cover)
ink.text((500, 868), "PAVAROTTI", font=ImageFont.truetype(args.serif, 88),
         anchor="mm", fill="#e9e1d4", stroke_width=0)
ink.line((362, 959, 638, 959), fill="#85382d", width=2)
cover.resize((500, 500), Image.Resampling.LANCZOS).save(ROOT / "assets/portada.png")
seal = Image.open(ROOT / "assets/sello.png").resize((256, 256), Image.Resampling.LANCZOS)
seal.save(ROOT / "assets/pavarotti.ico", sizes=[(n, n) for n in (16, 24, 32, 40, 48, 64, 128, 256)])
