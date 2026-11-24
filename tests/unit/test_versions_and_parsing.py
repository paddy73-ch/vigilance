import pytest

from vigilance.cve.cvss import cvss3_base_score, score_to_severity
from vigilance.cve.ecosystems import ghsa_ecosystem, osv_ecosystem
from vigilance.cve.matcher import AffectedRange, check_version_in_range, compare_debian_versions
from vigilance.cve.osv import parse_vuln, tool_query_key
from vigilance.cve.ghsa import parse_advisory
from vigilance.cve.sync import cve_affects_names
from vigilance.cve.models import CVEData
from vigilance.discovery.osinfo import parse_os_release
from vigilance.discovery.packages import parse_apk_output, parse_dpkg_output


def _sign(x):
    return (x > 0) - (x < 0)


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("3.11.2-6+deb12u6", "3.11.2-6+deb12u7", -1),  # security fix in the Debian revision
    ("1.0~rc1", "1.0", -1),
    ("1:0.1", "2.0", 1),  # epoch wins
    ("2.41.5-0+deb13u1", "2.42-1", -1),
    ("5.8.1-1+deb13u2", "5.8.1-1", 1),
    ("3.5.9-1~deb13u1", "3.5.9-1", -1),  # tilde sorts before everything
    ("1.0+b1", "1.0", 1),
    ("1.2.3", "1.2.3-0", 0),
])
def test_compare_debian_versions(a, b, expected):
    assert _sign(compare_debian_versions(a, b)) == expected


def test_debian_range_uses_revision():
    r = AffectedRange(type="DEBIAN", introduced="0", fixed="3.11.2-6+deb12u7")
    assert check_version_in_range("3.11.2-6+deb12u6", r).affected is True
    assert check_version_in_range("3.11.2-6+deb12u7", r).affected is False


@pytest.mark.parametrize("vector,score,severity", [
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
])
def test_cvss3(vector, score, severity):
    assert cvss3_base_score(vector) == score
    assert score_to_severity(score) == severity


def test_cvss_invalid():
    assert cvss3_base_score("CVSS:4.0/AV:N") is None
    assert cvss3_base_score("garbage") is None


def test_os_release_and_ecosystems():
    info = parse_os_release('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
    assert (info.id, info.version_id, info.codename) == ("debian", "13", "trixie")
    assert osv_ecosystem("dpkg", info.id, info.version_id) == "Debian:13"
    assert osv_ecosystem("dpkg", "ubuntu", "24.04") == "Ubuntu:24.04:LTS"
    assert osv_ecosystem("dpkg", "ubuntu", "25.10") == "Ubuntu:25.10"
    assert osv_ecosystem("apk", "alpine", "3.20.3") == "Alpine:v3.20"
    assert osv_ecosystem("dpkg", None, None) is None  # unknown release -> do not query bare "Debian"
    assert osv_ecosystem("docker", "debian", "13") is None
    assert ghsa_ecosystem("pip") == "pip"
    assert ghsa_ecosystem("dpkg") is None


def test_parse_dpkg_with_source_package():
    pkgs = parse_dpkg_output(
        "libssl3t64\t3.5.9-1~deb13u1\tamd64\topenssl\t3.5.9-1~deb13u1\tSecure Sockets Layer toolkit\n"
        "libpython3.13-minimal\t3.13.5-2+deb13u5\tamd64\tpython3.13\t3.13.5-2+deb13u5\tMinimal subset\n"
        "zlib1g\t1:1.3.dfsg+really1.3.1-1+b1\tamd64\tzlib\t1:1.3.dfsg+really1.3.1-1\tcompression\n"
    )
    assert [(p.name, p.source_name) for p in pkgs] == [
        ("libssl3t64", "openssl"), ("libpython3.13-minimal", "python3.13"), ("zlib1g", "zlib")]
    # binNMU: binary version differs from the source version
    assert pkgs[2].source_version == "1:1.3.dfsg+really1.3.1-1"


def test_parse_dpkg_legacy_format():
    pkgs = parse_dpkg_output("nginx\t1.26.3-3\tamd64\tsmall web server\n")
    assert pkgs[0].source_name == "nginx" and pkgs[0].source_version == "1.26.3-3"


def test_parse_apk_list_installed():
    pkgs = parse_apk_output(
        "libcrypto3-3.3.2-r0 x86_64 {openssl} (Apache-2.0) [installed]\n"
        "busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [installed]\n"
    )
    assert [(p.name, p.version, p.source_name) for p in pkgs] == [
        ("libcrypto3", "3.3.2-r0", "openssl"), ("busybox", "1.36.1-r29", "busybox")]


# Shape of a real OSV record (DEBIAN-CVE-2026-78410, Nov 2026): fixed in forky only
OSV_DEBIAN = {
    "id": "DEBIAN-CVE-2026-78410",
    "modified": "2026-11-05T09:47:31.161879Z",
    "upstream": ["CVE-2026-78410"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {"package": {"name": "util-linux", "ecosystem": "Debian:13"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
         "ecosystem_specific": {"urgency": "not yet assigned"}},
        {"package": {"name": "util-linux", "ecosystem": "Debian:14"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.42.3-1"}]}]},
    ],
}


def test_parse_osv_vuln():
    cve = parse_vuln(OSV_DEBIAN)
    assert cve.cve_id == "DEBIAN-CVE-2026-78410"
    assert cve.title == "CVE-2026-78410"
    assert cve.severity == "HIGH" and cve.cvss_score == 7.8
    by_eco = {r.ecosystem: r for r in cve.affected_ranges}
    assert by_eco["Debian:13"].fixed is None  # no fix for trixie yet
    assert by_eco["Debian:14"].fixed == "2.42.3-1"
    assert cve.raw_data["_vigilance_parser"] >= 2


def test_osv_urgency_fallback():
    vuln = {**OSV_DEBIAN, "severity": [], "affected": [
        {"package": {"name": "x", "ecosystem": "Debian:13"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-2"}]}],
         "ecosystem_specific": {"urgency": "medium"}}]}
    assert parse_vuln(vuln).severity == "MEDIUM"


def test_tool_query_key_uses_source_package():
    from types import SimpleNamespace
    inv = SimpleNamespace(os_id="debian", os_version_id="13")
    tool = SimpleNamespace(package_manager="dpkg", tool_name="libssl3t64", detected_version="3.5.9-1~deb13u1",
                           source_name="openssl", source_version="3.5.9-1~deb13u1", inventory=inv)
    assert tool_query_key(tool) == ("Debian:13", "openssl", "3.5.9-1~deb13u1")
    tool.inventory = SimpleNamespace(os_id=None, os_version_id=None)
    assert tool_query_key(tool) is None


def test_parse_ghsa_rest_advisory():
    node = {
        "ghsa_id": "GHSA-q238-5cxm-5c9h", "cve_id": "CVE-2026-15830", "summary": "Django issue",
        "severity": "medium", "html_url": "https://github.com/advisories/GHSA-q238-5cxm-5c9h",
        "cvss": {"vector_string": None, "score": None},
        "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1}},
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "django"},
                             "vulnerable_version_range": "< 5.2.17", "first_patched_version": "5.2.17"}],
    }
    cve = parse_advisory(node)
    assert cve.cve_id == "GHSA-q238-5cxm-5c9h"
    assert cve.title.startswith("CVE-2026-15830")
    assert cve.severity == "MEDIUM"
    assert cve.affected_ranges[0].fixed == "5.2.17"
    assert cve.affected_ranges[0].ecosystem == "pip"


def test_name_filter_is_exact():
    names = {"openssl", "libtext-iconv-perl", "curl"}
    def cve(repo):
        return CVEData(cve_id="X", source="nvd", affected_ranges=[AffectedRange(type="ECOSYSTEM", repo=repo)])
    assert cve_affects_names(cve("openssl"), names)
    assert not cve_affects_names(cve("perl"), names)  # no substring matches any more
    assert not cve_affects_names(cve("libcurl"), names)
    assert cve_affects_names(cve("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"), names)


def test_parse_dpkg_skips_not_installed():
    pkgs = parse_dpkg_output(
        "ii \tlibssl3t64\t3.5.9-1~deb13u1\tamd64\topenssl\t3.5.9-1~deb13u1\tSSL toolkit\n"
        "rc \tlibglib2.0-0\t2.74.6-2+deb12u7\tamd64\tglib2.0\t2.74.6-2+deb12u7\tGLib (config files only)\n"
        "hi \tlibfoo\t1.0\tamd64\tfoo\t1.0\theld package\n"
        "bar\t1\tall\tbar\t1\tline without status column\n"
    )
    assert [p.name for p in pkgs] == ["libssl3t64", "libfoo", "bar"]


def test_interfaces_ip():
    from vigilance.discovery.orchestrator import DiscoveryOrchestrator
    ifaces = [{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": "192.0.2.69/24"}]
    assert DiscoveryOrchestrator._ip_from_interfaces(ifaces) == "192.0.2.69"
    assert DiscoveryOrchestrator._ip_from_interfaces([{"name": "lo", "inet": "127.0.0.1/8"}]) is None
