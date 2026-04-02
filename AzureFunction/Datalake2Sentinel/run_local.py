import constants
from launch import start
from logger import Logger

if __name__ == "__main__":
    logger = Logger._create_logger()

    logger.info("Start Datalake2Sentinel")
    try:
        start(logger, run_as_cron=constants.RUN_AS_CRON)
    finally:
        logger.info("End Datalake2Sentinel")
