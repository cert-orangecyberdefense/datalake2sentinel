import asyncio
import json
import time
import uuid
import ipaddress
import requests
import logging
from ratelimit import limits, sleep_and_retry
from .constants import (
    AZURE_SCOPE,
    AZURE_AUTHORITY_URL,
    BATCH_SIZE,
    REQUESTS_PER_MINUTE,
    SOURCE_SYSTEM_NAME,
)
from msal import ConfidentialClientApplication
from datetime import datetime, timedelta
from stix2 import Indicator, exceptions
from datalake import Datalake, Output
from .exceptions import DatalakeError, DatalakeConnectionError, DatalakeAuthenticationError, DatalakePermissionError


class Datalake2Sentinel:
    """
    A class that handles all the logic of the connector: getting the iocs from
    Datalake, transform them into STIX indicator's objects and send them to Sentinel.
    """

    def __init__(self, logger, tenant, certificate, datalake, config):
        self.logger = logger
        self.dtlLongTermToken = datalake.get("dtlLongTermToken")
        self.dtlEnvironment = datalake.get("dtlEnvironment", "prod")
        self.clientId = tenant["clientId"]
        self.tenantId = tenant["tenantId"]
        self.clientCredential = (
            certificate if certificate else tenant["clientCredential"]
        )
        self.workspaceId = tenant["workspaceId"]
        self.dtlQueries = getattr(config, "datalake_queries", [])
        self.dtlAddScoreLabels = getattr(config, "add_score_labels", True)
        self.dtlAddThreatEntitiesLabels = getattr(
            config, "add_threat_entities_as_labels", False
        )
        self.dtlAddThreatTagsLabels = getattr(
            config, "add_threat_tags_as_labels", False
        )
        self.dtlThreatDownloadTimeout = getattr(
            config, "threats_download_timeout", 15 * 60
        )

        self.dtl = Datalake(
            longterm_token=self.dtlLongTermToken,
            env=self.dtlEnvironment,
            log_level=logging.ERROR
        )

        try:
            self.currentUserInfo = self.dtl.MyAccount.me()
        except ConnectionError as e:
            raise DatalakeConnectionError(f"Unable to connect to Datalake: {e}")
        except ValueError as e:
            raise DatalakeAuthenticationError(f"Authentication error: {e}")
        except Exception as e:
            raise DatalakeError(f"Unexpected error: {e}")

        self.logger.debug(
            f"""
                Init of Datlake2Sentinel done
                on tenant {self.tenantId} and workspace {self.workspaceId} for client {self.clientId}
                with options for Datalake set as :
                - nb of queries : {len(self.dtlQueries)}
                - scores labels : {self.dtlAddScoreLabels}
                - threat entities labels : {self.dtlAddThreatEntitiesLabels}
                - threat tags labels: {self.dtlAddThreatTagsLabels}
            """
        )

    def _checkpermission(self, name):
        permissions = self.currentUserInfo["role"]["administration_permissions"]
        for permission in permissions:
            if name == permission["name"]:
                return True
        return False

    def _getDalakeThreats(self):
        if not self._checkpermission("bulk_search"):
            raise DatalakePermissionError("User doesn't have bulk_search permission. Please check your datalake credentials and permissions")

        query_fields = [
            "atom_type",
            "atom_value",
            "threat_hashkey",
            "last_updated",
            ".hashes.md5",
            ".hashes.sha1",
            ".hashes.sha256",
            "threat_scores",
        ]
        if self.dtlAddScoreLabels:
            query_fields.append("threat_types")
        if self.dtlAddThreatEntitiesLabels or self.dtlAddThreatTagsLabels:
            query_fields.append("threat_entities")
            query_fields.append("tags")

        coroutines = []
        results = []

        try:
            for query in self.dtlQueries:
                self.logger.info(
                    f"Creating BulkSearch for {query['query_hash']} query_hash ..."
                )

                task = self.dtl.BulkSearch.create_task(
                    query_hash=query["query_hash"], query_fields=query_fields
                )
                coroutines.append(
                    task.download_async(
                        output=Output.JSON, timeout=self.dtlThreatDownloadTimeout
                    )
                )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(asyncio.gather(*coroutines))
                for result in results:
                    self.logger.info(
                        "Get {} threats from Datalake with {} query_hash".format(
                            result["count"], result["advanced_query_hash"]
                        )
                    )
            finally:
                loop.close()
        except TimeoutError:
            raise DatalakeError(
                f"Download timeout exceeded {self.dtlThreatDownloadTimeout}s"
            )
        except Exception as e:
            raise DatalakeError(f"Failed to retrieve threats: {e}")

        return results

    def _return_threat_as_dict(self, threat):
        return {
            "atom_type": threat[0],
            "atom_value": threat[1],
            "threat_hashkey": threat[2],
            "last_updated": threat[3],
            ".hashes.md5": threat[4],
            ".hashes.sha1": threat[5],
            ".hashes.sha256": threat[6],
            "threat_scores": threat[7],
            "threat_types": threat[8] if self.dtlAddScoreLabels else None,
            "threat_entities": (
                threat[len(threat) - 2] if self.dtlAddThreatEntitiesLabels else None
            ),
            "threat_tags": (
                threat[len(threat) - 1] if self.dtlAddThreatEntitiesLabels else None
            ),
        }

    def _generateStixIndicators(self, bulk_searches_results):
        stix_indicators = []
        self.logger.info("Generating STIX indicators ...")

        for index, bulk_search_result in enumerate(bulk_searches_results):
            query_hash = bulk_search_result["advanced_query_hash"]
            input_label = self.dtlQueries[index]["label"]
            valid_until = datetime.now() + timedelta(
                hours=self.dtlQueries[index]["valid_until"]
            )

            for threat in bulk_search_result["results"]:
                threat = self._return_threat_as_dict(threat)
                try:
                    stix_indicators.append(
                        Indicator(
                            type="indicator",
                            id="indicator--{}".format(
                                uuid.uuid5(
                                    uuid.NAMESPACE_OID,
                                    query_hash
                                    + input_label
                                    + threat.get("threat_hashkey"),
                                )
                            ),
                            name=threat.get("atom_value"),
                            pattern=self._create_stix_pattern(
                                threat.get("atom_value"),
                                threat.get("atom_type"),
                                threat.get(".hashes.md5"),
                                threat.get(".hashes.sha1"),
                                threat.get(".hashes.sha256"),
                            ),
                            pattern_type="stix",
                            valid_from=threat.get("last_updated"),
                            valid_until=valid_until.isoformat() + "Z",
                            labels=self._create_stix_labels(
                                input_label=input_label,
                                threat_types=threat.get("threat_types"),
                                threat_scores=threat.get("threat_scores"),
                                threat_entities=threat.get("threat_entities"),
                                threat_tags=threat.get("threat_tags"),
                            ),
                            confidence=max(threat.get("threat_scores")),
                            external_references=[
                                {
                                    "source_name": "Orange Cyberdefense",
                                    "url": "https://datalake.cert.orangecyberdefense.com/gui/threat/{}".format(
                                        threat.get("threat_hashkey")
                                    ),
                                }
                            ],
                        )
                    )
                except exceptions.InvalidValueError as e:
                    self.logger.error(
                        f"An error occured when creating stix indicator for threat {threat} : {e}"
                    )
                except Exception as e:
                    self.logger.error(f"{e}")

        self.logger.info("STIX indicators generated")

        return stix_indicators

    def _create_stix_pattern(
        self, atom_value, atom_type, hashes_md5, hashes_sha1, hashes_sha256
    ):
        pattern_format = "[{}:{} = {}]"

        if atom_type == "domain":
            return pattern_format.format("domain-name", "value", repr(atom_value))
        elif atom_type == "url":
            return pattern_format.format("url", "value", repr(atom_value))
        elif atom_type == "email":
            return pattern_format.format("email-addr", "value", repr(atom_value))
        elif atom_type == "ip":
            try:
                if isinstance(ipaddress.ip_address(atom_value), ipaddress.IPv4Address):
                    return pattern_format.format("ipv4-addr", "value", repr(atom_value))
                elif isinstance(
                    ipaddress.ip_address(atom_value), ipaddress.IPv6Address
                ):
                    return pattern_format.format("ipv6-addr", "value", repr(atom_value))
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
            raise Exception(f"Atom type '{atom_type}' is unknown or is not handled")

    def _create_stix_labels(
        self, input_label, threat_types, threat_scores, threat_entities, threat_tags
    ):
        stix_labels = [input_label]

        if threat_entities:
            stix_labels.extend(threat_entities)

        if threat_tags:
            stix_labels.extend(threat_tags)

        if threat_types:
            max_score = max(threat_scores) - (max(threat_scores) % 10)
            max_score = max_score if max_score < 100 else 90
            stix_labels.append("dtl_score_" + str(max_score))

            for index, threat_type in enumerate(threat_types):
                stix_labels.append(
                    "dtl_score_{}_{}".format(
                        threat_type, threat_scores[index] - (threat_scores[index] % 10)
                    )
                )

        return stix_labels

    def _getAzureAppToken(self):
        self.logger.info(f"Generating new Azure token ...")

        client_id = self.clientId
        tenant_id = self.tenantId
        client_credential = self.clientCredential

        app = ConfidentialClientApplication(
            client_id=client_id,
            authority=AZURE_AUTHORITY_URL + tenant_id,
            client_credential=client_credential,
        )

        acquire_tokens_result = app.acquire_token_for_client(scopes=[AZURE_SCOPE])

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

        batch_index = 0
        retry = 0

        while batch_index < num_batches:
            # Extract the batch
            start_index = batch_index * BATCH_SIZE
            end_index = start_index + BATCH_SIZE
            batch = indicators[start_index:end_index]

            # Send the request
            response = self._send_request(batch, access_token)

            if response.status_code == 429:
                self.logger.debug(
                    f"Error HTTP 429. Rate Limit reached. Waiting for {response.headers['Retry-After']} seconds before retrying batch"
                )
                time.sleep(int(response.headers["Retry-After"]))
            elif retry == 0 and response.status_code in (504, 503):
                self.logger.warning(
                    f"Error HTTP {response.status_code}. Possible temporary issue. Waiting for 1 minute before retrying once"
                )
                time.sleep(60)
                retry += 1
            else:
                if response.status_code != 200:
                    # We already retried once or error unhandled yet, we log and go to next batch
                    self.logger.error(
                        f"Error HTTP {response.status_code} occured for current batch, text/reason : {response.text} and {response.reason}"
                    )
                batch_index = batch_index + 1
                retry = 0

        self.logger.debug(
            f"Successful upload of {batch_index} batches to Azure Sentinel"
        )


    @sleep_and_retry
    @limits(calls=REQUESTS_PER_MINUTE, period=60)
    def _send_request(self, indicators, access_token):
        workspace_id = self.workspaceId
        upload_indicator_url = f"https://api.ti.sentinel.azure.com/workspaces/{workspace_id}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        data_to_upload = {
            "sourcesystem": SOURCE_SYSTEM_NAME,
            "stixobjects": [
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
        try:
            bulk_searches_results = self._getDalakeThreats()
        except DatalakeError as e:
            self.logger.error(e)
            return

        indicators = self._generateStixIndicators(bulk_searches_results)
        self._batch_post_requests(indicators)

        return
