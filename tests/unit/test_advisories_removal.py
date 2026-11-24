"""Merging advisories of the same CVE; obsolete package detection and removal-check parsing."""
from vigilance.cve.advisories import cves_of, merge_advisories, same_vulnerability, vuln_key
from vigilance.discovery.packages import PackageInfo
from vigilance.discovery.removal import SCRIPT, obsolete_binaries, parse_check_output


def test_vuln_key():
    assert vuln_key("CVE-2026-109518") == "CVE-2026-109518"
    assert vuln_key("DEBIAN-CVE-2026-109518") == "CVE-2026-109518"
    assert vuln_key("DSA-6607-1", "CVE-2026-109518,DEBIAN-CVE-2026-109518") == "CVE-2026-109518"
    assert vuln_key("DSA-6000-1", ["CVE-2026-1111", "CVE-2026-2222"]) is None
    assert vuln_key("GHSA-xxxx", []) is None
    assert cves_of("DSA-1", "CVE-2026-1111,DEBIAN-CVE-2026-1111,CVE-2026-2222") == ["CVE-2026-1111", "CVE-2026-2222"]


def test_merge_advisories():
    rows = [
        {"id": "DEBIAN-CVE-2026-1111", "upstream": ["CVE-2026-1111"], "severity": "NONE", "cvss": None, "hosts": 1},
        {"id": "DSA-6607-1", "upstream": ["CVE-2026-1111", "DEBIAN-CVE-2026-1111"], "severity": "HIGH", "cvss": 7.5, "hosts": 3},
        {"id": "DEBIAN-CVE-2026-2222", "upstream": ["CVE-2026-2222"], "severity": "LOW", "cvss": None, "hosts": 1},
        {"id": "DSA-6000-1", "upstream": ["CVE-2026-1111", "CVE-2026-2222"], "severity": "HIGH", "cvss": None, "hosts": 1},
        {"id": "DSA-7000-1", "upstream": ["CVE-2026-1111", "CVE-2026-9999"], "severity": "LOW", "cvss": None, "hosts": 1},
    ]
    out = {r["label"]: r for r in merge_advisories(rows, max_fields=("hosts",))}
    assert set(out) == {"CVE-2026-1111", "CVE-2026-2222", "DSA-7000-1"}
    # the more severe advisory represents the group
    assert out["CVE-2026-1111"]["id"] == "DSA-6607-1" and out["CVE-2026-1111"]["hosts"] == 3
    assert set(out["CVE-2026-1111"]["also"]) == {"DEBIAN-CVE-2026-1111", "DSA-6000-1"}
    assert out["CVE-2026-2222"]["also"] == ["DSA-6000-1"]
    # covers a CVE not otherwise listed: stays on its own
    assert out["DSA-7000-1"]["also"] == []


def test_same_vulnerability():
    assert same_vulnerability("DEBIAN-CVE-2026-1111", "DSA-6607-1", "CVE-2026-1111")
    assert same_vulnerability("DSA-6607-1", "DSA-6607-1", None)
    assert not same_vulnerability("DSA-6607-1", "DEBIAN-CVE-2026-1111", "CVE-2026-1111")  # DSA ID alone has no CVE
    assert not same_vulnerability("DEBIAN-CVE-2026-1111", "DEBIAN-CVE-2026-2222", "CVE-2026-2222")


def _pkg(name, src, ver):
    return PackageInfo(name=name, version=ver, source_name=src, source_version=ver)


def test_obsolete_binaries():
    pkgs = [
        _pkg("apt", "apt", "3.0.4"), _pkg("libapt-pkg7.0", "apt", "3.0.4"), _pkg("libapt-pkg6.0", "apt", "2.6.1"),
        _pkg("libperl5.36", "perl", "5.36.0-7+deb12u2"), _pkg("perl-modules-5.36", "perl", "5.36.0-7+deb12u2"),
        _pkg("perl", "perl", "5.40.1-6"), _pkg("curl", "curl", "8.14.1-2"),
        PackageInfo(name="busybox", version="1.36", manager="apk"),
    ]
    assert obsolete_binaries(pkgs) == ["libapt-pkg6.0", "libperl5.36", "perl-modules-5.36"]


def test_parse_check_output():
    out = "\n".join([
        "##PKG libapt-pkg6.0", "##SIM Purg libapt-pkg6.0",
        "##PKG perl-modules-5.36", "##SIM Purg libperl5.36", "##SIM Purg perl-modules-5.36",
        "##USE 812 /usr/sbin/old-daemon --foreground", "##EXT /opt/tool/bin/x", "##AVAIL no", "##LIBS 2",
        "##PKG broken", "##SIMERR E: Unable to locate package broken",
    ])
    r = parse_check_output(out, ["libapt-pkg6.0", "perl-modules-5.36", "broken"])
    assert r["libapt-pkg6.0"]["would_remove"] == ["libapt-pkg6.0"]
    assert r["perl-modules-5.36"]["would_remove"] == ["libperl5.36", "perl-modules-5.36"]
    assert r["perl-modules-5.36"]["in_use"] == [{"pid": 812, "command": "/usr/sbin/old-daemon --foreground"}]
    assert r["perl-modules-5.36"]["external"] == ["/opt/tool/bin/x"]
    assert r["broken"]["error"].startswith("E: Unable")
    assert r["perl-modules-5.36"]["reinstallable"] is False and r["libapt-pkg6.0"]["reinstallable"] is None
    assert r["perl-modules-5.36"]["libraries"] == 2 and r["libapt-pkg6.0"]["libraries"] is None


def test_script_is_read_only():
    # the check must never change anything on the host
    assert "apt-get -s" in SCRIPT
    assert "Dir::Log::Planner=/dev/null" in SCRIPT  # otherwise -s still writes /var/log/apt/eipp.log.xz
    import re
    body = SCRIPT.replace("apt-get -s", "")
    for forbidden in (r"apt-get\s+(purge|remove|install)", r"\bdpkg\s+-[rPi]", r"(^|[\s;|&])rm\s", r"[^2]>\s*/(?!dev/null)"):
        assert not re.search(forbidden, body, re.M), forbidden


def test_parse_header():
    from vigilance.discovery.removal import parse_header
    assert parse_header("##KERNEL 7.0.14-30-pve\n##PKG a\n##NOROOT") == {"root": True, "kernel": "7.0.14-30-pve"}
    assert parse_header("##NOROOT\n##KERNEL 6.12\n##PKG a") == {"root": False, "kernel": "6.12"}


def test_script_reports_root_and_kernel():
    assert '[ "$(id -u)" = 0 ] || echo "##NOROOT"' in SCRIPT and "##KERNEL $(uname -r)" in SCRIPT



def test_parse_upgrade_output():
    from vigilance.discovery.removal import UPGRADE_SCRIPT, parse_upgrade_output
    r = parse_upgrade_output("##LISTS 1764000000\n##UPG curl 8.14.1-2+deb13u8\n##UPG libfoo:amd64 2")
    assert r["candidates"] == {"curl": "8.14.1-2+deb13u8", "libfoo:amd64": "2"} and r["lists_at"].startswith("2025-")
    assert "apt list --upgradable" in UPGRADE_SCRIPT and "pkgcache.bin" in UPGRADE_SCRIPT and "ls -t /var/lib/apt/lists" not in UPGRADE_SCRIPT 
    import re
    assert not re.search(r"^\s*apt(-get)?\s+update", UPGRADE_SCRIPT, re.M)  # never refreshes the lists


def test_parse_kernel_output():
    from vigilance.discovery.removal import KERNEL_SCRIPT, parse_kernel_output
    out = "\n".join(["##KERNEL 7.0.14-30-pve", "##KPKG rc linux-image-6.12.95+deb13-rt-amd64",
                     "##KPKG ii linux-image-rt-amd64", "##KSIM busybox", "##KSIM wireguard", "##KSIM initramfs-tools",
                     "##KSIM linux-image-rt-amd64", "##KSIM dracut-install", "##KSIM linux-base"])
    k = parse_kernel_output(out)
    assert [p["name"] for p in k["packages"]] == ["linux-image-6.12.95+deb13-rt-amd64", "linux-image-rt-amd64"]
    assert k["extra"] == ["wireguard"] and k["running_kernel"] == "7.0.14-30-pve"
    assert parse_kernel_output("") is None
    assert "--autoremove purge" in KERNEL_SCRIPT and "apt-get -s" in KERNEL_SCRIPT
