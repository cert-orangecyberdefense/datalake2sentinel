import config

# Constants for accessing threats fields
ATOM_TYPE = 0
ATOM_VALUE = 1
THREAT_HASHKEY = 2
LAST_UPDATED = 3
HASHES_MD5 = 4
HASHES_SHA1 = 5
HASHES_SHA256 = 6
THREAT_SCORES = 7
THREAT_TYPES = 8 if config.add_score_labels else None
if config.add_threat_entities_as_labels and config.add_score_labels:
    SUBCATEGORIES = 9
else:
    if not config.add_threat_entities_as_labels:
        SUBCATEGORIES = None
    elif not config.add_score_labels and config.add_threat_entities_as_labels:
        SUBCATEGORIES = 8

# Azure
AZURE_SCOPE = ["https://management.azure.com/.default"]
AZURE_AUTHORITY_URL = "https://login.microsoftonline.com/"
BATCH_SIZE = 100
REQUESTS_PER_MINUTE = 100
SOURCE_SYSTEM_NAME = "Datalake - OrangeCyberdefense"
