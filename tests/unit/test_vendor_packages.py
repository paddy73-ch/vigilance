"""Packages from vendor apt repositories: Go module mapping, OSV query keys, origin detection."""
import json
from types import SimpleNamespace

import pytest

from vigilance.cve import osv
from vigilance.cve.ecosystems import upstream_version, vendor_go_module
from vigilance.cve.findings import fixed_version_for
from vigilance.discovery.removal import UPGRADE_SCRIPT, parse_upgrade_output


def test_upstream_version():
    assert upstream_version("5:29.10.0-1~debian.13~trixie") == "29.10.0"
    assert upstream_version("2.4.2-4~debian.13~trixie") == "2.4.2"
    assert upstream_version("1.90.6") == "1.90.6"


def test_vendor_go_module():
    assert vendor_go_module("tailscale", "1.38.1") == ("tailscale.com", "1.38.1")
    assert vendor_go_module("containerd.io", "2.4.2-4~debian.13~trixie") == ("github.com/containerd/containerd/v2", "2.4.2")
    assert vendor_go_module("containerd.io", "1.7.27-1") == ("github.com/containerd/containerd", "1.7.27")
    assert vendor_go_module("crowdsec", "1.8.2") == ("github.com/crowdsecurity/crowdsec", "1.8.2")
    # deliberately not mapped: no reliable version mapping
    assert vendor_go_module("docker-ce", "5:29.10.0-1~debian.13~trixie") is None
    assert vendor_go_module("curl", "8.14.1-2") is None


def _tool(name, version, src=None):
    inv = SimpleNamespace(os_id="debian", os_version_id="13")
    return SimpleNamespace(tool_name=name, detected_version=version, source_name=src or name,
                           source_version=version, package_manager="dpkg", inventory=inv)


def test_osv_query_key_uses_go_for_vendor_packages():
    assert osv.tool_query_key(_tool("tailscale", "1.38.1")) == ("Go", "tailscale.com", "1.38.1")
    assert osv.tool_query_key(_tool("containerd.io", "2.4.2-4~debian.13~trixie")) == \
        ("Go", "github.com/containerd/containerd/v2", "2.4.2")
    assert osv.tool_query_key(_tool("curl", "8.14.1-2")) == ("Debian:13", "curl", "8.14.1-2")


def test_fixed_version_from_go_advisory():
    vuln = {"id": "GHSA-vfgq-g5x8-g595", "aliases": ["CVE-2023-28436"], "summary": "x",
            "affected": [{"package": {"name": "tailscale.com", "ecosystem": "Go"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.34.0"}, {"fixed": "1.38.2"}]}]}]}
    data = osv.parse_vuln(vuln)
    cve = SimpleNamespace(affected_ranges=json.dumps([r.__dict__ if hasattr(r, "__dict__") else r for r in data.affected_ranges]))
    assert fixed_version_for(cve, "Go", "tailscale.com") == "1.38.2"


def test_parse_origins():
    out = "\n".join(["##UPG curl 8.14.1-2+deb13u8",
                     "##ORIGIN docker-ce https://download.docker.com/linux/debian",
                     "##ORIGIN curl http://deb.debian.org/debian", "##ORIGIN curl http://security.debian.org/debian-security"])
    r = parse_upgrade_output(out)
    assert r["origins"]["docker-ce"] == ["https://download.docker.com/linux/debian"]
    assert len(r["origins"]["curl"]) == 2
    assert "apt-cache policy" in UPGRADE_SCRIPT


def test_foreign_sources():
    from vigilance.api.routes.views import foreign_sources
    check = json.dumps({"origins": {
        "curl": ["http://deb.debian.org/debian"],
        "libfoo": ["http://192.0.2.104:3142/deb.debian.org/debian"],  # through apt-cacher-ng
        "docker-ce": ["https://download.docker.com/linux/debian"],
        "containerd.io": ["https://download.docker.com/linux/debian"],
        "pve-manager": ["http://download.proxmox.com/debian/pve"],
    }})
    groups = {g["source"]: g for g in foreign_sources(check, {"containerd.io": "2.4.2-4~debian.13~trixie"})}
    assert set(groups) == {"download.docker.com", "download.proxmox.com"}
    assert groups["download.docker.com"]["uncovered"] == ["docker-ce"]
    assert groups["download.docker.com"]["covered"] == [{"package": "containerd.io",
                                                          "module": "github.com/containerd/containerd/v2"}]
    assert foreign_sources(None, {}) == []
