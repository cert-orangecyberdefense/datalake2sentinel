import config
from AzureFunction.Datalake2Sentinel.logger import Logger
from AzureFunction.Datalake2Sentinel.launch import main
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    logger = Logger._create_logger(config)

    logger.info("Start Datalake2Sentinel")
    main(logger, config, None, getattr(config, "run_as_cron", False))
    logger.info("End Datalake2Sentinel")
