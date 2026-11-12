"""Read-only local check of stored TOTP against Python's independent standard library.

Never prints a seed, account, enrollment URI, or OTP. Historical test outputs are
sent only to a local child through stdin, not arguments, files, or logs.
"""
import base64
import ctypes as c
from ctypes import wintypes as w
import hashlib
import hmac
from pathlib import Path
import struct
import subprocess
from urllib.parse import parse_qs, urlsplit


class Credential(c.Structure):
    _fields_ = [("Flags", w.DWORD), ("Type", w.DWORD), ("TargetName", w.LPWSTR),
                ("Comment", w.LPWSTR), ("LastWritten", w.FILETIME),
                ("BlobSize", w.DWORD), ("Blob", c.POINTER(c.c_ubyte)),
                ("Persist", w.DWORD), ("AttributeCount", w.DWORD),
                ("Attributes", c.c_void_p), ("TargetAlias", w.LPWSTR), ("UserName", w.LPWSTR)]


def main():
    api = c.WinDLL("advapi32", use_last_error=True)
    records_type = c.POINTER(c.POINTER(Credential))
    api.CredEnumerateW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(w.DWORD), c.POINTER(records_type)]
    api.CredEnumerateW.restype = w.BOOL
    api.CredFree.argtypes = [c.c_void_p]
    count, records = w.DWORD(), records_type()
    expected = []
    if api.CredEnumerateW("OwnVPN/*", 0, c.byref(count), c.byref(records)):
        try:
            bindings = []
            for index in range(count.value):
                record = records[index].contents
                target = record.TargetName
                if "/totp/" not in target:
                    continue
                suffix = target.rsplit("/totp/", 1)[1]
                if len(suffix) != 64 or any(ch not in "0123456789abcdef" for ch in suffix):
                    continue
                uri = c.string_at(record.Blob, record.BlobSize).decode("utf-16-le")
                fields = parse_qs(urlsplit(uri).query)
                secret = fields["secret"][0]
                key = base64.b32decode(secret + "=" * (-len(secret) % 8))
                period = int(fields["period"][0])
                bindings.append((target, key, period))
            # There is one company binding in this diagnostic session. Avoid an
            # ambiguous multi-account comparison without disclosing identities.
            if len(bindings) != 1:
                print("reference_check_requires_one_binding")
                return 1
            _, key, period = bindings[0]
            for algorithm in (hashlib.sha1, hashlib.sha256, hashlib.sha512):
                for timestamp in (0, 59, 1234567890, 20000000000):
                    digest = hmac.new(key, struct.pack(">Q", timestamp // period), algorithm).digest()
                    offset = digest[-1] & 15
                    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
                    expected.append(f"{binary % 1000000:06d}")
        finally:
            for index in range(count.value):
                record = records[index].contents
                if record.Blob and record.BlobSize:
                    c.memset(record.Blob, 0, record.BlobSize)
            api.CredFree(records)
    else:
        print("no_binding_visible_to_reference_check")
        return 1
    executable = Path(__file__).resolve().parents[1] / "build" / "totp_diagnose.exe"
    result = subprocess.run([str(executable), "--oracle"], input="\n".join(expected),
                            text=True, encoding="utf-8", capture_output=True, timeout=15)
    print(result.stdout.strip())
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
