import logging
import os
import schedule
import time
import config
from Datalake2Sentinel import Datalake2Sentinel
from dotenv import load_dotenv

load_dotenv()


def _build_logger():
    logger = logging.getLogger("datalake2sentinel")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(os.environ["LOG_FILE"], mode="a")
    handler.setLevel(logging.INFO)
    if config.verbose_log:
        handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def main():
    datalake2Sentinel = Datalake2Sentinel(logger)
    if config.run_as_cron:
        schedule.every(config.upload_frequency).hours.do(
            datalake2Sentinel.uploadIndicatorsToSentinel
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        datalake2Sentinel.uploadIndicatorsToSentinel()


if __name__ == "__main__":
    logger = _build_logger()

    logger.info("Start Datalake2Sentinel")
    main()
    logger.info("End Datalake2Sentinel")
