"""
© https://github.com/YouFoundTheDev | 2026
test_smoke.py
"""

import airlock


def test_package_imports() -> None:
    assert airlock.__version__


def test_the_public_surface_is_exported() -> None:
    for name in airlock.__all__:
        assert getattr(airlock, name) is not None


def test_the_documented_entry_points_exist() -> None:
    assert callable(airlock.compose)
    assert callable(airlock.outbound_surfaces)
    assert airlock.Ruling.PERMIT.value == "permit"
    assert airlock.Weight.CRITICAL > airlock.Weight.INFO
