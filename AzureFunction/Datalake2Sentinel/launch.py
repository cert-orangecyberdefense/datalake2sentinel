import time

import constants
import exceptions as exc
import schedule
from Datalake2Sentinel import Datalake2Sentinel


def start(logger, certificate=None, run_as_cron: bool = False):
    try:
        datalake2Sentinel = Datalake2Sentinel(logger, certificate)
    except exc.DatalakeError as e:
        logger.error(str(e))
        raise SystemExit(1)

    if run_as_cron:
        schedule.every(constants.UPLOAD_FREQUENCY).hours.do(
            datalake2Sentinel.uploadIndicatorsToSentinel
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        datalake2Sentinel.uploadIndicatorsToSentinel()
