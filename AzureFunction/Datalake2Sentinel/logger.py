import logging
import os
import sys


class Logger:
    @staticmethod
    def _create_logger(config):
        """This logger both saves its logs at /tmp/datalake2sentinel.log and prints them to the terminal"""
        logger = logging.getLogger("datalake2sentinel")
        logger.setLevel(logging.INFO)
        if getattr(config, "verbose_log", False):
            logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(
            os.getenv("log_file", "/tmp/datalake2sentinel.log"), mode="a"
        )
        file_handler.setLevel(logging.INFO)
        if getattr(config, "verbose_log", False):
            file_handler.setLevel(logging.DEBUG)

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(logging.INFO)
        if getattr(config, "verbose_log", False):
            stream_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        return logger
