"""
Unit tests for Scrutics classifier modules.
These tests do not require a live network interface.
"""

import pytest
from scrutics.classifier.protocol import classify_by_ports, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW
from scrutics.classifier.oui import lookup_vendor, is_ot_vendor
from scrutics.db.inventory import AssetInventory


# ── Protocol Classifier Tests ──────────────────────────────────────────────

class TestProtocolClassifier:

    def test_modbus_port_classified_as_ot(self):
        result = classify_by_ports({502})
        assert result["is_ot"] is True
        assert result["confidence"] == CONFIDENCE_HIGH
        assert "Modbus TCP" in result["protocols"]

    def test_s7comm_port_classified_as_siemens(self):
        result = classify_by_ports({102})
        assert result["is_ot"] is True
        assert "Siemens PLC" in result["role"]

    def test_dnp3_port_classified_as_utility(self):
        result = classify_by_ports({20000})
        assert result["is_ot"] is True
        assert "DNP3" in result["protocols"]

    def test_it_only_ports_classified_correctly(self):
        result = classify_by_ports({80, 443, 22})
        assert result["is_ot"] is False
        assert result["confidence"] == CONFIDENCE_MEDIUM

    def test_unknown_ports_return_low_confidence(self):
        result = classify_by_ports({9999, 12345})
        assert result["confidence"] == CONFIDENCE_LOW
        assert result["is_ot"] is None

    def test_multiple_ics_ports_detected_as_hmi(self):
        result = classify_by_ports({502, 102, 44818})
        assert result["is_ot"] is True
        assert "multi-protocol" in result["role"]
        assert len(result["protocols"]) > 1


# ── OUI Lookup Tests (using known MAC prefixes) ───────────────────────────

class TestOUILookup:

    def test_unknown_mac_returns_unknown(self):
        # Use a zeroed-out OUI that won't be in the database
        result = lookup_vendor("00:00:00:00:00:00", {})
        assert result == "Unknown"

    def test_known_oui_returns_vendor(self):
        # Inject a fake OUI DB entry for testing
        fake_db = {"AABBCC": "Siemens AG"}
        result = lookup_vendor("AA:BB:CC:DD:EE:FF", fake_db)
        assert result == "Siemens AG"

    def test_mac_format_with_dashes(self):
        fake_db = {"AABBCC": "Moxa Technologies"}
        result = lookup_vendor("AA-BB-CC-DD-EE-FF", fake_db)
        assert result == "Moxa Technologies"

    def test_is_ot_vendor_siemens(self):
        assert is_ot_vendor("Siemens AG") is True

    def test_is_ot_vendor_moxa(self):
        assert is_ot_vendor("Moxa Technologies Co., Ltd.") is True

    def test_is_ot_vendor_dell_is_false(self):
        assert is_ot_vendor("Dell Inc.") is False


# ── Asset Inventory Tests ─────────────────────────────────────────────────

class TestAssetInventory:

    def test_new_asset_created_on_first_packet(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        assert inv.count() == 1

    def test_packet_count_increments(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        assert inv.get("10.0.0.1").packet_count == 2

    def test_peer_ip_tracked(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", dst_ip="10.0.0.2")
        assert "10.0.0.2" in inv.get("10.0.0.1").peer_ips

    def test_port_tracked(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", dst_port=502)
        assert 502 in inv.get("10.0.0.1").ports_seen

    def test_multiple_assets(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        inv.update(ip="10.0.0.2", mac="11:22:33:44:55:66")
        assert inv.count() == 2

    def test_to_dict_has_required_keys(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        d = inv.get("10.0.0.1").to_dict()
        for key in ["ip", "mac", "vendor", "role", "confidence", "packet_count"]:
            assert key in d
