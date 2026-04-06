import os
import logging
from dotenv import load_dotenv

load_dotenv()


def get_bool_env(name: str, default: bool = False) -> bool:
    """
    Parse a boolean environment variable

    Avoids using `distutils.util.strtobool` which becomes deprecated starting with Python 3.10
    and is removed in Python 3.12
    """
    return os.getenv(name, str(default)).lower() in {"true", "1", "yes"}


# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", logging.INFO)
LOG_FILE = os.getenv("LOG_FILE")


# Datalake
DATALAKE_TOKEN = os.getenv("DATALAKE_TOKEN")
DATALAKE_ENV = os.getenv("DATALAKE_ENV", "prod")
DATALAKE_QUERIES = os.getenv(
    "DATALAKE_QUERIES",
    '[{"query_hash": "14d206c952ca80e8a5de09cb2ed21d40", "label": "malicious_ips", "valid_until": 1}]',
)

# Azure
CLIENT_ID = os.getenv("CLIENT_ID")
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_CREDENTIAL = os.getenv("CLIENT_CREDENTIAL")
WORKSPACE_ID = os.getenv("WORKSPACE_ID")
CLIENT_CERTIFICATE = os.getenv("CLIENT_CERTIFICATE")

AZURE_SCOPE = os.getenv("AZURE_SCOPE", "https://management.azure.com/.default")
AZURE_AUTHORITY_URL = os.getenv("AZURE_AUTHORITY_URL", "https://login.microsoftonline.com/")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 100))
REQUESTS_PER_MINUTE = int(os.getenv("REQUESTS_PER_MINUTE", 100))
SOURCE_SYSTEM_NAME = os.getenv("SOURCE_SYSTEM_NAME", "Datalake - OrangeCyberdefense")
ADD_SCORE_LABELS = get_bool_env("ADD_SCORE_LABELS", True)
ADD_THREAT_ENTITIES_AS_LABELS = get_bool_env("ADD_THREAT_ENTITIES_AS_LABELS", True)
ADD_THREAT_TAGS_AS_LABELS = get_bool_env("ADD_THREAT_TAGS_AS_LABELS", True)

THREATS_DOWNLOAD_TIMEOUT_SEC = int(os.getenv("THREATS_DOWNLOAD_TIMEOUT_SEC", 1800))
TRIGGER_SCHEDULE = os.getenv("TRIGGER_SCHEDULE", "0 0 * * *")

RUN_AS_CRON = get_bool_env("RUN_AS_CRON", False)
