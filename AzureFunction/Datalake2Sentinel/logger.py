import logging
import os


class Logger:
    @staticmethod
    def _create_logger(config):
        logger = logging.getLogger("datalake2sentinel")
        logger.setLevel(logging.INFO)
        if getattr(config, "verbose_log", False):
            logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(
            os.getenv("log_file", "/tmp/datalake2sentinel.log"), mode="a"
        )
        handler.setLevel(logging.INFO)
        if getattr(config, "verbose_log", False):
            handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
