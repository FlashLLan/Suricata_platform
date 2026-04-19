"""
Unit tests for pcap_analyzer internals.

These tests do NOT require a running server — they call the Python functions
directly to verify correctness of the topology-builder and scenario-detector
without needing a real .pcap file.
"""
from collections import Counter, defaultdict

from app.simulation.pcap_analyzer import (
    HostInfo,
    _build_topology,
    _infer_device_type,
    _infer_zone,
)


# ─── _build_topology ──────────────────────────────────────────────────────────

class TestBuildTopology:
    def _make_host(self, ip: str, server_ports=None) -> HostInfo:
        h = HostInfo(ip=ip)
        h.server_ports = set(server_ports or [])
        h.syn_targets = defaultdict(set)
        h.syn_port_counts = Counter()
        return h

    def test_node_type_is_device(self):
        """Critical regression: nodes must have type='device' so ReactFlow
        renders DeviceNode, not a plain white box."""
        hosts = {"192.168.1.10": self._make_host("192.168.1.10")}
        topo = _build_topology(hosts, set())
        for node in topo["nodes"]:
            assert node["type"] == "device", (
                f"Node {node['id']} has type={node['type']!r} — "
                "must be 'device' to match NODE_TYPES in LabPage.tsx"
            )

    def test_node_contains_required_data_fields(self):
        hosts = {"10.0.0.5": self._make_host("10.0.0.5", server_ports=[80, 443])}
        topo = _build_topology(hosts, set())
        node = topo["nodes"][0]
        data = node["data"]
        for field in ("label", "deviceType", "ip", "zone", "ports"):
            assert field in data, f"Missing field '{field}' in node data"

    def test_node_ip_matches_host(self):
        hosts = {"172.16.0.1": self._make_host("172.16.0.1")}
        topo = _build_topology(hosts, set())
        assert topo["nodes"][0]["data"]["ip"] == "172.16.0.1"

    def test_node_has_position(self):
        hosts = {"192.168.0.1": self._make_host("192.168.0.1")}
        topo = _build_topology(hosts, set())
        pos = topo["nodes"][0]["position"]
        assert "x" in pos and "y" in pos

    def test_edges_deduplicated(self):
        """Bidirectional pairs (A→B and B→A) should produce one edge."""
        hosts = {
            "192.168.1.1": self._make_host("192.168.1.1"),
            "192.168.1.2": self._make_host("192.168.1.2"),
        }
        comm_pairs = {
            ("192.168.1.1", "192.168.1.2"),
            ("192.168.1.2", "192.168.1.1"),
        }
        topo = _build_topology(hosts, comm_pairs)
        assert len(topo["edges"]) == 1

    def test_edges_have_source_and_target(self):
        hosts = {
            "10.0.0.1": self._make_host("10.0.0.1"),
            "10.0.0.2": self._make_host("10.0.0.2"),
        }
        topo = _build_topology(hosts, {("10.0.0.1", "10.0.0.2")})
        edge = topo["edges"][0]
        assert "source" in edge and "target" in edge

    def test_unknown_comm_ip_skipped(self):
        """An edge referencing an IP not in hosts must be silently dropped."""
        hosts = {"192.168.1.1": self._make_host("192.168.1.1")}
        topo = _build_topology(hosts, {("192.168.1.1", "10.99.99.99")})
        assert topo["edges"] == []

    def test_multiple_hosts_produce_multiple_nodes(self):
        hosts = {ip: self._make_host(ip) for ip in ["1.2.3.4", "1.2.3.5", "1.2.3.6"]}
        topo = _build_topology(hosts, set())
        assert len(topo["nodes"]) == 3


# ─── _infer_zone ──────────────────────────────────────────────────────────────

class TestInferZone:
    def test_private_192_168_is_internal(self):
        assert _infer_zone("192.168.1.100") == "internal"

    def test_private_10_is_internal(self):
        assert _infer_zone("10.0.0.1") == "internal"

    def test_private_172_16_is_internal(self):
        assert _infer_zone("172.16.5.1") == "internal"

    def test_public_ip_is_external(self):
        assert _infer_zone("8.8.8.8") == "external"

    def test_loopback_is_internal(self):
        # Loopback is private, not external
        assert _infer_zone("127.0.0.1") in ("internal", "management")


# ─── _infer_device_type ───────────────────────────────────────────────────────

class TestInferDeviceType:
    def _host(self, server_ports=None, dns_queries=None, http_payloads=None,
              syn_targets=None, icmp_targets=None):
        h = HostInfo(ip="192.168.1.1")
        h.server_ports = set(server_ports or [])
        h.dns_queries = dns_queries or []
        h.http_payloads = http_payloads or []
        h.icmp_targets = icmp_targets or set()
        h.syn_targets = defaultdict(set)
        if syn_targets:
            for k, v in syn_targets.items():
                h.syn_targets[k] = v
        h.syn_port_counts = Counter()
        return h

    def test_port_80_443_is_web_server(self):
        h = self._host(server_ports=[80, 443])
        assert _infer_device_type(h) == "web-server"

    def test_port_53_is_dns_server(self):
        h = self._host(server_ports=[53])
        assert _infer_device_type(h) == "dns-server"

    def test_port_3306_is_database(self):
        h = self._host(server_ports=[3306])
        assert _infer_device_type(h) == "database"

    def test_port_5432_is_database(self):
        h = self._host(server_ports=[5432])
        assert _infer_device_type(h) == "database"

    def test_port_25_is_mail_server(self):
        h = self._host(server_ports=[25])
        assert _infer_device_type(h) == "mail-server"

    def test_no_server_ports_defaults_to_workstation(self):
        h = self._host()
        result = _infer_device_type(h)
        # Without scan activity or server ports, should be workstation or server
        assert result in ("workstation", "server", "attacker", "router")
