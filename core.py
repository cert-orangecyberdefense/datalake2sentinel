from AzureFunction.Datalake2Sentinel.logger import Logger
from AzureFunction.Datalake2Sentinel.launch import main
from AzureFunction.Datalake2Sentinel.constants import RUN_AS_CRON

if __name__ == "__main__":
    logger = Logger._create_logger()

    logger.info("Start Datalake2Sentinel")
    main(logger, None, RUN_AS_CRON)
    logger.info("End Datalake2Sentinel")
