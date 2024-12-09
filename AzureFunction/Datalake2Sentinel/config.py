# Datalake queries (bulk search) with query_hash
datalake_queries = [
  {
    "query_hash":"14d206c952ca80e8a5de09cb2ed21d40",
    "label":"malicious_ips",
    "valid_until":1 # in hours
  },
  {
    "query_hash":"2e310c7f15ce1887b024e275fc05b19a",
    "label":"peerpressure_cobaltstrike_c2",
    "valid_until":240 # in hours
  }
]

# Add Datalake scores as labels in Azure Sentinel 
add_score_labels = True

# Add Datalake threat entities (subcategories) as labels in Azure Sentinel
add_threat_entities_as_labels = True 

# Logger config
verbose_log = False

# Add Datalake threat tags as labels in Azure Sentinel
add_threat_tags_as_labels = True