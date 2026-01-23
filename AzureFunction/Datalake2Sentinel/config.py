# Datalake queries (bulk search) with query_hash
datalake_queries = [
  {
    "query_hash":"14d206c952ca80e8a5de09cb2ed21d40",
    "label":"malicious_ips",
    "valid_until":1 # in hours
  }
]

# Add Datalake scores as labels in Azure Sentinel 
add_score_labels = True

# Add Datalake threat entities as labels in Azure Sentinel
add_threat_entities_as_labels = True 

# Add Datalake threat tags as labels in Azure Sentinel
add_threat_tags_as_labels = True

# Logger config
verbose_log = False
# Optional Configuration for the local use only
# Cron schedule of the integration (in hours), default values are False and 1
#run_as_cron = False
#upload_frequency = 1 
