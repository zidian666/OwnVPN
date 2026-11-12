"""Rebuild the code-drawn O icon; developer-only dependency: Pillow.

Geometry matches resources/app-icon.svg. No runtime Python dependency.
"""
from pathlib import Path
from PIL import Image, ImageDraw

resources = Path(__file__).resolve().parents[1] / "resources"
scale = 4
image = Image.new("RGBA", (256 * scale, 256 * scale))
draw = ImageDraw.Draw(image)

def box(values):
    return tuple(value * scale for value in values)

teal = (0, 119, 106, 255)
for connected in (False, True):
    image = Image.new("RGBA", (256 * scale, 256 * scale))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(box((8, 8, 248, 248)), radius=56 * scale, fill=teal)
    draw.ellipse(box((70, 52, 186, 204)), fill=(255, 211, 90, 255) if connected else "white")
    draw.ellipse(box((94, 78, 162, 178)), fill=teal)
    image = image.resize((256, 256), Image.Resampling.LANCZOS)
    image.save(resources / ("app-icon-connected.png" if connected else "app-icon.png"))
    image.save(resources / ("app-connected.ico" if connected else "app.ico"),
               sizes=[(n, n) for n in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
