import asyncio
import os
import config
import uuid
import re
import ipaddress
from datetime import datetime, timedelta
from stix2 import Indicator, DomainName, IPv4Address, IPv6Address, URL, File
from datalake import Datalake, Output
from dotenv import load_dotenv

load_dotenv()

# Constants for accessing threats fields (default)
ATOM_TYPE = 0
ATOM_VALUE = 1
TAGS = 2
THREAT_HASHKEY = 3
LAST_UPDATED = 4
THREAT_TYPES = 5 if config.add_score_labels else None
THREAT_SCORES = 6 if config.add_score_labels else None
if config.add_threat_entities_as_labels and config.add_score_labels:
    SUBCATEGORIES = 7
else:
    if not config.add_threat_entities_as_labels:
        SUBCATEGORIES = None
    elif not config.add_score_labels and config.add_threat_entities_as_labels:
        SUBCATEGORIES = 5


class Datalake2Sentinel:
    """
    A class that handles all the logic of the connector: getting the iocs from
    Datalake, transform them into STIX indicator's object and send them to Sentinel.
    """

    def __init__(self, logger):
        self.logger = logger

    def _getDalakeThreats(self):
        query_fields = [
            "atom_type",
            "atom_value",
            "tags",
            "threat_hashkey",
            "last_updated",
        ]
        if config.add_score_labels:
            query_fields.append("threat_types")
            query_fields.append("threat_scores")
        if config.add_threat_entities_as_labels:
            query_fields.append("subcategories")

        dtl = Datalake(
            username=os.environ["OCD_DTL_USERNAME"],
            password=os.environ["OCD_DTL_PASSWORD"],
        )
        coroutines = []

        for query in config.datalake_queries:
            task = dtl.BulkSearch.create_task(
                query_hash=query["query_hash"], query_fields=query_fields
            )
            coroutines.append(task.download_async(output=Output.JSON))

        loop = asyncio.get_event_loop()
        future = asyncio.gather(*coroutines)
        results = loop.run_until_complete(future)
        for result in results:
            self.logger.info(
                "Get {} threats from Datalake with {} query_hash".format(
                    result["count"], result["advanced_query_hash"]
                )
            )

        return results

    def _generateStixIndicators(self, bulk_searches_results):
        stix_indicators = []

        for index, bulk_search_result in enumerate(bulk_searches_results):
            query_hash = bulk_search_result["advanced_query_hash"]
            input_label = config.datalake_queries[index]["label"]
            valid_until = datetime.now() + timedelta(
                hours=config.datalake_queries[index]["valid_until"]
            )

            for threat in bulk_search_result["results"]:
                stix_indicators.append(
                    Indicator(
                        type="indicator",
                        id="indicator--{}".format(
                            uuid.uuid5(uuid.NAMESPACE_OID, query_hash + input_label)
                        ),
                        name=threat[ATOM_VALUE],
                        pattern=self._create_stix_pattern(threat[ATOM_VALUE]),
                        pattern_type="stix",
                        valid_from=threat[LAST_UPDATED],
                        valid_until=valid_until.isoformat() + "Z",
                        labels=self._create_stix_labels(
                            threat[TAGS],
                            threat[THREAT_TYPES],
                            threat[THREAT_SCORES],
                            threat[SUBCATEGORIES],
                        ),
                        external_references=[
                            {
                                "source_name": "Orange Cyberdefense",
                                "url": "https://datalake.cert.orangecyberdefense.com/gui/threat/{}".format(
                                    threat[THREAT_HASHKEY]
                                ),
                            }
                        ],
                    )
                )

        return stix_indicators

    def _create_stix_pattern(self, atom_value):
        indicator_type = self._identify_indicator_type(atom_value)

        if indicator_type:
            pattern_format = "[{}:{} = '{}']"
            if indicator_type == "ipv4-addr":
                return pattern_format.format("ipv4-addr", "value", atom_value)
            elif indicator_type == "ipv6-addr":
                return pattern_format.format("ipv6-addr", "value", atom_value)
            elif indicator_type == "domain-name":
                return pattern_format.format("domain-name", "value", atom_value)
            elif indicator_type == "url":
                return pattern_format.format("url", "value", atom_value)
            elif indicator_type == "file-hash":
                return pattern_format.format("file", "hashes.MD5", atom_value)
            else:
                return "Unknown indicator type"
        else:
            return "Unknown indicator type"

    def _identify_indicator_type(self, atom_value):
        try:
            if isinstance(ipaddress.ip_address(atom_value), ipaddress.IPv4Address):
                return "ipv4-addr"
            elif isinstance(ipaddress.ip_address(atom_value), ipaddress.IPv6Address):
                return "ipv6-addr"
        except ValueError:
            pass

        if re.match(r"^(http|https)://", atom_value, re.IGNORECASE):
            return "url"
        elif re.match(
            r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,}$",
            atom_value,
        ):
            return "domain-name"
        elif re.match(
            r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", atom_value
        ):
            return "file-hash"

        return None

    def _create_stix_labels(self, tags, threat_types, threat_scores, subcategories):
        stix_labels = []
        stix_labels = stix_labels + tags

        for subcategory in subcategories:
            stix_labels.append(subcategory)

        if threat_types:
            stix_labels.append("dtl_score_" + str(max(threat_scores)))

            for index, threat_type in enumerate(threat_types):
                stix_labels.append(
                    "dtl_score_{}_{}".format(threat_type, threat_scores[index])
                )

        return stix_labels

    def _getAzureAppToken(self):
        pass

    def _uploadIndicatorsToSentinel(self):
        pass
