import pytest
import json
from core import _build_logger
from Datalake2Sentinel import Datalake2Sentinel
from unittest import mock

logger = _build_logger()

ipv4 = "0.0.0.0"
ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
url = "https://www.google.com"
file = "dccffd34ed20d9b20480d99045606af1"
fqdn = "www.google.com"
md5 = "098f6bcd4621d373cade4e832627b4f6"
sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

bs_results = [
    {
        "bulk_search_hash": "0290b7530bdfeac34aa2fccc34d1ec0b",
        "advanced_query_hash": "2e310c7f15ce1887b024e275fc05b19a",
        "query_fields": [
            "atom_type",
            "atom_value",
            "threat_hashkey",
            "last_updated",
            ".hashes.md5",
            ".hashes.sha1",
            ".hashes.sha256",
            "threat_scores",
            "threat_types",
            "subcategories",
        ],
        "for_stix_export": False,
        "task_uuid": "fbdd3bdf-532d-457c-a9e3-21768d59aefe",
        "results": [
            [
                "ip",
                "43.139.67.239",
                "7468ffb21b36a569b1dc74b1fc93fbb8",
                "2022-10-12T00:42:02Z",
                "",
                "",
                "",
                [93, 1, 0],
                ["malware", "hack", "phishing"],
                [
                    "OCD - Threat pattern:Command and Control [C2]",
                    "Tool:Cobalt Strike - S0154",
                ],
            ],
            [
                "ip",
                "37.187.180.39",
                "1ab0dd530060ff0934f29d8a8195cf47",
                "2022-10-12T00:42:02Z",
                "",
                "",
                "",
                [100],
                ["malware"],
                [
                    "Malware:Bumblebee - S1039",
                    "OCD - Threat pattern:Command and Control [C2]",
                ],
            ],
            [
                "ip",
                "154.22.168.135",
                "15ba40c947d0a322c14fa3d0e7c30eb3",
                "2022-10-12T00:42:02Z",
                "",
                "",
                "",
                [100],
                ["malware"],
                [
                    "OCD - Threat pattern:Command and Control [C2]",
                    "Tool:Cobalt Strike - S0154",
                ],
            ],
        ],
    }
]

datalake2Sentinel = Datalake2Sentinel(logger=logger)


def test_create_stix_pattern():
    assert (
        datalake2Sentinel._create_stix_pattern(ipv4, "ip", "", "", "")
        == "[ipv4-addr:value = '0.0.0.0']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(ipv6, "ip", "", "", "")
        == "[ipv6-addr:value = '2001:0db8:85a3:0000:0000:8a2e:0370:7334']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(url, "url", "", "", "")
        == "[url:value = 'https://www.google.com']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(
            file, "file", "098f6bcd4621d373cade4e832627b4f6", "", ""
        )
        == "[file:hashes.MD5 = '098f6bcd4621d373cade4e832627b4f6']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(
            file,
            "file",
            "098f6bcd4621d373cade4e832627b4f6",
            "",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )
        == "[file:hashes.MD5 = '098f6bcd4621d373cade4e832627b4f6' OR file:hashes.SHA256 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(
            file,
            "file",
            "098f6bcd4621d373cade4e832627b4f6",
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )
        == "[file:hashes.MD5 = '098f6bcd4621d373cade4e832627b4f6' OR file:hashes.SHA1 = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3' OR file:hashes.SHA256 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']"
    )
    assert (
        datalake2Sentinel._create_stix_pattern(fqdn, "fqdn", "", "", "")
        == "[domain-name:value = 'www.google.com']"
    )
    with pytest.raises(Exception) as e:
        datalake2Sentinel._create_stix_pattern(".", "test", "", "", "")
        assert "unknown" in str(e)


def test_create_stix_labels():
    input_label = "query_label"
    threat_types = ["malware", "hack", "phishing"]
    threat_scores = [93, 1, 0]
    subcategories = [
        "OCD - Threat pattern:Command and Control [C2]",
        "Tool:Cobalt Strike - S0154",
    ]

    assert datalake2Sentinel._create_stix_labels(
        input_label, threat_types, threat_scores, subcategories
    ) == [
        "query_label",
        "OCD - Threat pattern:Command and Control [C2]",
        "Tool:Cobalt Strike - S0154",
        "dtl_score_90",
        "dtl_score_malware_90",
        "dtl_score_hack_0",
        "dtl_score_phishing_0",
    ]


def test_generateStixIndicators():
    stix_indicators = datalake2Sentinel._generateStixIndicators(bs_results)
    assert len(stix_indicators) == 3
