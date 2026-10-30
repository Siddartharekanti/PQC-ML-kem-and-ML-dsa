"""
QFF 2026 Phase 2 - PQC track environment check.  RUN THIS FIRST.

    python common/env_check.py

What it does
  1. Checks the Python version and that the kit libraries import.
  2. Runs a correctness self-test of every algorithm used in the track
     (ML-KEM, ML-DSA, SLH-DSA, RSA, ECDH/ECDSA, X25519/Ed25519, HKDF, AES-256-GCM).
  3. Records your machine details (this is your Platform A description) in
     platform_A_info.json - commit that file to your repository.

Exit code 0 = ready.  Any FAIL line tells you exactly what to fix.
"""
import json
import os
import platform
import sys
import time

OK, FAIL = "  [ OK ]", "  [FAIL]"
results = {"checks": {}}


def check(name, fn):
    try:
        detail = fn()
        print(f"{OK} {name}" + (f"  - {detail}" if detail else ""))
        results["checks"][name] = "ok"
        return True
    except Exception as e:  # noqa: BLE001
        print(f"{FAIL} {name}  - {type(e).__name__}: {e}")
        results["checks"][name] = f"fail: {e}"
        return False


def py_version():
    v = sys.version_info
    if v < (3, 10):
        raise RuntimeError(f"Python {v.major}.{v.minor} found; Python 3.10 or newer is required")
    return platform.python_version()


def libs():
    import cryptography
    import pqcrypto  # noqa: F401
    import psutil
    try:
        from importlib.metadata import version
        pv = version("pqcrypto")
    except Exception:  # noqa: BLE001
        pv = "?"
    results["versions"] = {"cryptography": cryptography.__version__, "pqcrypto": pv, "psutil": psutil.__version__}
    return f"cryptography {cryptography.__version__}, pqcrypto {pv}, psutil {psutil.__version__}"


def mlkem():
    from cryptography.hazmat.primitives.asymmetric import mlkem as m
    sk = m.MLKEM768PrivateKey.generate()
    ss, ct = sk.public_key().encapsulate()
    assert sk.decapsulate(ct) == ss
    bad = bytearray(ct); bad[0] ^= 1
    assert sk.decapsulate(bytes(bad)) != ss, "tampered ciphertext gave same secret"
    return f"ML-KEM-768 pk={len(sk.public_key().public_bytes_raw())} B, ct={len(ct)} B, ss={len(ss)} B"


def mldsa():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa as m
    sk = m.MLDSA65PrivateKey.generate()
    sig = sk.sign(b"qff2026")
    sk.public_key().verify(sig, b"qff2026")
    try:
        sk.public_key().verify(sig, b"qff2027")
        raise AssertionError("modified message verified")
    except InvalidSignature:
        pass
    return f"ML-DSA-65 pk={len(sk.public_key().public_bytes_raw())} B, sig={len(sig)} B"


def slhdsa():
    from pqcrypto.sign import slh_dsa_sha2_128s as s
    pk, sk = s.keygen()
    sig = s.sign(sk, b"qff2026")
    s.verify(pk, b"qff2026", sig)
    try:
        s.verify(pk, b"qff2027", sig)
        raise AssertionError("modified message verified")
    except Exception as e:  # noqa: BLE001
        if isinstance(e, AssertionError):
            raise
    return f"SLH-DSA-SHA2-128s pk={len(pk)} B, sig={len(sig)} B"


def classical():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
    r = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = r.sign(b"m", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    r.public_key().verify(sig, b"m", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    e = ec.generate_private_key(ec.SECP256R1())
    e.public_key().verify(e.sign(b"m", ec.ECDSA(hashes.SHA256())), b"m", ec.ECDSA(hashes.SHA256()))
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    assert a.exchange(b.public_key()) == b.exchange(a.public_key())
    k = ed25519.Ed25519PrivateKey.generate()
    k.public_key().verify(k.sign(b"m"), b"m")
    return "RSA-2048, ECDSA/ECDH P-256, X25519, Ed25519"


def symmetric():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qff").derive(b"\x01" * 32)
    n = os.urandom(12)
    ct = AESGCM(key).encrypt(n, b"hello", b"ad")
    assert AESGCM(key).decrypt(n, ct, b"ad") == b"hello"
    return "HKDF-SHA256 + AES-256-GCM"


def interop():
    from cryptography.hazmat.primitives.asymmetric import mlkem as m
    from pqcrypto.kem import ml_kem_768 as k
    sk = m.MLKEM768PrivateKey.generate()
    ct, ss = k.encaps(sk.public_key().public_bytes_raw())
    assert sk.decapsulate(ct) == ss
    return "cryptography <-> pqcrypto ML-KEM-768 interoperate"


def platform_info():
    import psutil
    freq = psutil.cpu_freq()
    info = {
        "platform_label": "A",
        "recorded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "machine": platform.machine(),
        "cpu_model": platform.processor() or "see os tools",
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_max_mhz": round(freq.max, 0) if freq and freq.max else None,
        "ram_total_gb": round(psutil.virtual_memory().total / 2**30, 2),
        "python": platform.python_version(),
        "python_impl": platform.python_implementation(),
        "on_battery": None,
    }
    try:
        b = psutil.sensors_battery()
        info["on_battery"] = (not b.power_plugged) if b else False
    except Exception:  # noqa: BLE001
        pass
    if sys.platform.startswith("linux"):
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    info["versions"] = results.get("versions", {})
    with open("platform_A_info.json", "w") as f:
        json.dump(info, f, indent=2)
    warn = "  (WARNING: on battery - plug in before benchmarking)" if info["on_battery"] else ""
    return f"{info['cpu_model']}, {info['logical_cores']} logical cores, {info['ram_total_gb']} GB -> platform_A_info.json{warn}"


if __name__ == "__main__":
    print("QFF 2026 Phase 2 - PQC environment check\n")
    ok = all([
        check("Python >= 3.10", py_version),
        check("Kit libraries import", libs),
        check("ML-KEM-768 encaps/decaps + tamper", mlkem),
        check("ML-DSA-65 sign/verify + tamper", mldsa),
        check("SLH-DSA-SHA2-128s sign/verify + tamper", slhdsa),
        check("Classical reference algorithms", classical),
        check("HKDF + AES-256-GCM", symmetric),
        check("Library interoperability", interop),
        check("Platform A description recorded", platform_info),
    ])
    print("\nREADY - environment is correct." if ok else
          "\nNOT READY - fix the FAIL lines (see KIT_GUIDE FAQ) and run again.")
    sys.exit(0 if ok else 1)
