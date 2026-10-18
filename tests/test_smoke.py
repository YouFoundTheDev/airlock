"""
© https://github.com/YouFoundTheDev | 2026
test_smoke.py
"""

import airlock


def test_package_imports() -> None:
    assert airlock.__version__
