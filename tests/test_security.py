"""pytest entry point for T1-T9 (same code as run_security_tests.py).

    python -m pytest -q            # T2 in sampled mode for speed
"""
import pytest

import security_suite as ss

LAB = ss.make_lab()
PAYLOADS = ss.load_all()


@pytest.mark.parametrize("suite", [ss.PQC, ss.CLASSICAL, ss.HYBRID], ids=lambda s: s.label)
@pytest.mark.parametrize("test_id", [t[0] for t in ss.TESTS])
def test_security(test_id, suite):
    cases = ss.run_test(test_id, LAB, suite, PAYLOADS, exhaustive=False)
    failed = [f"{c.name}: {c.observed}" for c in cases if not c.ok]
    assert cases and not failed, "\n".join(failed)
