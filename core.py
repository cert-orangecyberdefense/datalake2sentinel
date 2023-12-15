import logging
import os
from Datalake2Sentinel import Datalake2Sentinel
from dotenv import load_dotenv

load_dotenv()


def _build_logger():
    logger = logging.getLogger("datalake2sentinel")
    logger.setLevel(logging.INFO)
    if os.environ["VERBOSE_LOG"]:
        logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(os.environ["LOG_FILE"], mode="a")
    handler.setLevel(logging.INFO)
    if os.environ["VERBOSE_LOG"]:
        handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def main():
    pass


if __name__ == "__main__":
    logger = _build_logger()

    logger.info("Start Datalake2Sentinel")
    main()
    logger.info("End Datalake2Sentinel")
