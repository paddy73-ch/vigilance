import pytest

from vigilance.cve.matcher import (
    parse_debian_version,
    parse_semver,
    check_version_in_range,
    VersionMatch,
    AffectedRange,
)


def test_parse_semver():
    assert parse_semver("1.2.3") is not None
    assert str(parse_semver("1.2.3")) == "1.2.3"
    assert parse_semver("1.2.3-alpha") is not None
    assert parse_semver("invalid") is None


def test_parse_debian_version():
    # Standard versions
    assert parse_debian_version("1.2.3") is not None
    assert str(parse_debian_version("1.2.3")) == "1.2.3"

    # Debian revisions
    v = parse_debian_version("1.2.3-4")
    assert v is not None

    # With epoch (kept, it affects ordering)
    v = parse_debian_version("1:1.2.3-4")
    assert v is not None
    assert str(v) == "1:1.2.3-4"
    assert v > parse_debian_version("9.9.9-9")

    # Ubuntu style
    v = parse_debian_version("1.2.3-4ubuntu1")
    assert v is not None


def test_check_version_in_range_semver():
    # Version within range
    range_obj = AffectedRange(type="ECOSYSTEM", introduced="1.0.0", fixed="2.0.0")
    result = check_version_in_range("1.5.0", range_obj)
    assert result.affected is True
    assert result.fixed_version == "2.0.0"

    # Version before introduced
    result = check_version_in_range("0.9.0", range_obj)
    assert result.affected is False

    # Version at fixed (not affected)
    result = check_version_in_range("2.0.0", range_obj)
    assert result.affected is False

    # Version after fixed
    result = check_version_in_range("2.1.0", range_obj)
    assert result.affected is False


def test_check_version_in_range_debian():
    range_obj = AffectedRange(type="DEBIAN", introduced="1.0.0", fixed="1.2.3-4")
    result = check_version_in_range("1.1.0", range_obj)
    assert result.affected is True

    # Version at fixed (not affected)
    result = check_version_in_range("1.2.3-4", range_obj)
    assert result.affected is False


def test_check_version_in_range_last_affected():
    range_obj = AffectedRange(type="ECOSYSTEM", introduced="1.0.0", last_affected="1.9.9")
    result = check_version_in_range("1.5.0", range_obj)
    assert result.affected is True

    # Version after last_affected
    result = check_version_in_range("2.0.0", range_obj)
    assert result.affected is False


def test_check_version_in_range_unparsable():
    range_obj = AffectedRange(type="ECOSYSTEM", introduced="1.0.0", fixed="2.0.0")
    result = check_version_in_range("not-a-version", range_obj)
    assert result.affected is False
    assert "error" in result.details