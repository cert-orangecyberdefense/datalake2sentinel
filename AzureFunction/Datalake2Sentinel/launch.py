import json
import os
import schedule
import time
from .Datalake2Sentinel import Datalake2Sentinel


def main(logger, config, certificate, run_as_cron: bool = False):
    tenant = json.loads(os.getenv("tenant"))
    datalake = json.loads(os.getenv("datalake"))

    datalake2Sentinel = Datalake2Sentinel(logger, tenant, certificate, datalake, config)
    if run_as_cron:
        schedule.every(getattr(config, "upload_frequency", 1)).hours.do(
            datalake2Sentinel.uploadIndicatorsToSentinel
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        datalake2Sentinel.uploadIndicatorsToSentinel()
