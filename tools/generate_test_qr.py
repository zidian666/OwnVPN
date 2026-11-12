"""Generate public, synthetic enrollment fixtures; never use real account seeds.

Developer-only: pip install qrcode[pil]. The desktop app does not use Python.
"""
from pathlib import Path
import qrcode
from PIL import Image

fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
fixtures.mkdir(parents=True, exist_ok=True)
public_seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC test key, not an account.
uri = f"otpauth://totp/OwnVPN-Test:synthetic?secret={public_seed}&issuer=OwnVPN-Test"
image = qrcode.make(uri).convert("RGB")
image.save(fixtures / "totp-standard.png")
image.rotate(90, expand=True).save(fixtures / "totp-rotated.png")
qrcode.make("https://example.invalid/not-an-enrollment").save(fixtures / "not-totp.png")
double = Image.new("RGB", (image.width * 2 + 40, image.height), "white")
double.paste(image, (0, 0))
double.paste(image, (image.width + 40, 0))
double.save(fixtures / "multiple-qr.png")
Image.new("RGB", (300, 300), "white").save(fixtures / "blank.png")
