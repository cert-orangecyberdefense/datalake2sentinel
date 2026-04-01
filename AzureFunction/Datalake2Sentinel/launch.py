import schedule
import time
from .Datalake2Sentinel import Datalake2Sentinel
from .constants import UPLOAD_FREQUENCY
from .exceptions import DatalakeError


def main(logger, certificate, run_as_cron: bool = False):
    try:
        datalake2Sentinel = Datalake2Sentinel(logger, certificate)
    except DatalakeError as e:
        logger.error(e)
        return

    if run_as_cron:
        schedule.every(UPLOAD_FREQUENCY).hours.do(
            datalake2Sentinel.uploadIndicatorsToSentinel
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        datalake2Sentinel.uploadIndicatorsToSentinel()
