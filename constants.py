import config

# Constants for accessing threats fields
ATOM_TYPE = 0
ATOM_VALUE = 1
TAGS = 2
THREAT_HASHKEY = 3
LAST_UPDATED = 4
HASHES_MD5 = 5
HASHES_SHA1 = 6
HASHES_SHA256 = 7
THREAT_TYPES = 8 if config.add_score_labels else None
THREAT_SCORES = 9 if config.add_score_labels else None
if config.add_threat_entities_as_labels and config.add_score_labels:
    SUBCATEGORIES = 10
else:
    if not config.add_threat_entities_as_labels:
        SUBCATEGORIES = None
    elif not config.add_score_labels and config.add_threat_entities_as_labels:
        SUBCATEGORIES = 8
