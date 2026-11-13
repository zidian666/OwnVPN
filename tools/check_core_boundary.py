"""Reject platform SDK dependencies in the shared C++ core (Python stdlib)."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1] / "src" / "core"
forbidden = re.compile(r"\b(?:HANDLE|HWND|DWORD|HINSTANCE|BCrypt\w*|CredRead\w*|CredWrite\w*|GetAddrInfoEx\w*|SecureZeroMemory)\b")
failures = []
files = sorted(p for p in root.rglob("*") if p.suffix in {".h", ".cpp"})
for path in files:
    text = path.read_text(encoding="utf-8")
    for delimiter, include in re.findall(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', text, re.M):
        if delimiter == '"':
            target = (path.parent / include).resolve()
            if not target.is_relative_to(root.resolve()) or not target.is_file():
                failures.append(f"{path.name}: non-core include {include}")
        elif re.search(r"(?:windows|wincrypt|wincred|bcrypt|winsock|ws2tcpip|shellapi|shlobj|sddl|objbase|wincodec)\.h$", include, re.I):
            failures.append(f"{path.name}: platform SDK include {include}")
    for token in forbidden.findall(text):
        failures.append(f"{path.name}: platform symbol {token}")
if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
print(f"PASS: {len(files)} shared-core files contain no platform SDK dependencies")
