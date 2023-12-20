import asyncio
import json
import os
import config
import uuid
import ipaddress
import requests
from ratelimit import limits, sleep_and_retry
from constants import (
    ATOM_TYPE,
    ATOM_VALUE,
    TAGS,
    THREAT_HASHKEY,
    THREAT_SCORES,
    THREAT_TYPES,
    HASHES_MD5,
    HASHES_SHA1,
    HASHES_SHA256,
    LAST_UPDATED,
    SUBCATEGORIES,
    AZURE_SCOPE,
    AZURE_AUTHORITY_URL,
    BATCH_SIZE,
    REQUESTS_PER_MINUTE,
    SOURCE_SYSTEM_NAME,
)
from msal import ConfidentialClientApplication
from datetime import datetime, timedelta
from stix2 import Indicator
from datalake import Datalake, Output
from dotenv import load_dotenv

load_dotenv()


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
            ".hashes.md5",
            ".hashes.sha1",
            ".hashes.sha256",
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
        self.logger.info("Generating STIX indicators ...")

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
                            uuid.uuid5(
                                uuid.NAMESPACE_OID,
                                query_hash + input_label + threat[ATOM_VALUE],
                            )
                        ),
                        name=threat[ATOM_VALUE],
                        pattern=self._create_stix_pattern(
                            threat[ATOM_VALUE],
                            threat[ATOM_TYPE],
                            threat[HASHES_MD5],
                            threat[HASHES_SHA1],
                            threat[HASHES_SHA256],
                        ),
                        pattern_type="stix",
                        valid_from=threat[LAST_UPDATED],
                        valid_until=valid_until.isoformat() + "Z",
                        labels=self._create_stix_labels(
                            tags=threat[TAGS],
                            threat_types=threat[THREAT_TYPES] if THREAT_TYPES else None,
                            threat_scores=threat[THREAT_SCORES]
                            if THREAT_SCORES
                            else None,
                            subcategories=threat[SUBCATEGORIES]
                            if SUBCATEGORIES
                            else None,
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

        self.logger.info("STIX indicators generated")

        return stix_indicators

    def _create_stix_pattern(
        self, atom_value, atom_type, hashes_md5, hashes_sha1, hashes_sha256
    ):
        pattern_format = "[{}:{} = '{}']"

        if atom_type == "fqdn":
            return pattern_format.format("domain-name", "value", atom_value)
        elif atom_type == "url":
            return pattern_format.format("url", "value", atom_value)
        elif atom_type == "ip":
            try:
                if isinstance(ipaddress.ip_address(atom_value), ipaddress.IPv4Address):
                    return pattern_format.format("ipv4-addr", "value", atom_value)
                elif isinstance(
                    ipaddress.ip_address(atom_value), ipaddress.IPv6Address
                ):
                    return pattern_format.format("ipv6-addr", "value", atom_value)
            except ValueError:
                pass
        elif atom_type == "file":
            conditions = []

            if hashes_md5:
                conditions.append(f"file:hashes.MD5 = '{hashes_md5}'")
            if hashes_sha1:
                conditions.append(f"file:hashes.SHA1 = '{hashes_sha1}'")
            if hashes_sha256:
                conditions.append(f"file:hashes.SHA256 = '{hashes_sha256}'")
            if not conditions:
                return None

            pattern = " OR ".join(conditions)
            return f"[{pattern}]"

        else:
            return "Unknown indicator type"

    def _create_stix_labels(self, tags, threat_types, threat_scores, subcategories):
        stix_labels = []
        stix_labels = stix_labels + tags

        if subcategories:
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
        self.logger.info(f"Generating new Azure token ...")

        client_id = os.environ["CLIENT_ID"]
        tenant_id = os.environ["TENANT_ID"]
        client_credential = [os.environ["CLIENT_CREDENTIAL"]]

        app = ConfidentialClientApplication(
            client_id=client_id,
            authority=AZURE_AUTHORITY_URL + tenant_id,
            client_credential=client_credential,
        )

        acquire_tokens_result = app.acquire_token_for_client(scopes=AZURE_SCOPE)

        if "error" in acquire_tokens_result:
            self.logger.error(
                f"Error: {acquire_tokens_result['error']}\n"
                f"Description: {acquire_tokens_result['error_description']}"
            )
        else:
            self.logger.info(f"New Azure token acquired")
            return acquire_tokens_result["access_token"]

    def _batch_post_requests(self, indicators):
        num_batches = len(indicators) // BATCH_SIZE + (
            1 if len(indicators) % BATCH_SIZE else 0
        )
        access_token = self._getAzureAppToken()
        self.logger.info("Uploading indicators to Azure Sentinel ...")
        self.logger.debug(f"Uploading {num_batches} batches to Azure Sentinel ...")

        for i in range(num_batches):
            # Extract the batch
            start_index = i * BATCH_SIZE
            end_index = start_index + BATCH_SIZE
            batch = indicators[start_index:end_index]

            # Send the request
            self._send_request(batch, access_token)

        self.logger.debug(
            f"Successful upload of {num_batches} batches to Azure Sentinel"
        )
        self.logger.info("Successful upload of Indicators to Azure Sentinel")

    @sleep_and_retry
    @limits(calls=REQUESTS_PER_MINUTE, period=60)
    def _send_request(self, indicators, access_token):
        workspace_id = os.environ["WORKSPACE_ID"]
        upload_indicator_url = f"https://sentinelus.azure-api.net/workspaces/{workspace_id}/threatintelligenceindicators:upload?api-version=2022-07-01"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        data_to_upload = {
            "sourcesystem": SOURCE_SYSTEM_NAME,
            "indicators": [
                json.loads(indicator.serialize()) for indicator in indicators
            ],
        }

        data_to_upload = json.dumps(data_to_upload)

        response = requests.post(
            upload_indicator_url, headers=headers, data=data_to_upload
        )

        if response.status_code == 200:
            self.logger.debug("Successful upload of Indicators to Azure Sentinel")
        else:
            self.logger.error(
                f"An error occured when uploading Indicators to Azure Sentinel : {response.status_code}"
            )
        return response

    def uploadIndicatorsToSentinel(self):
        bulk_searches_results = self._getDalakeThreats()
        indicators = self._generateStixIndicators(bulk_searches_results)
        self._batch_post_requests(indicators)

        return
