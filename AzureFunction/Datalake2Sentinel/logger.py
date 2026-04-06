import logging
import sys
from logging.handlers import RotatingFileHandler

import constants


class Logger:
    @staticmethod
    def _create_logger():
        """This logger both saves its logs at /tmp/datalake2sentinel.log
        and prints them to the terminal
        """
        logger = logging.getLogger("datalake2sentinel")
        logger.setLevel(constants.LOG_LEVEL)

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(constants.LOG_LEVEL)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        stream_handler.setFormatter(formatter)

        if constants.LOG_FILE:
            file_handler = RotatingFileHandler(
                constants.LOG_FILE, mode="a", maxBytes=16000, backupCount=1
            )
            file_handler.setLevel(logging.INFO)
            file_handler.setLevel(constants.LOG_LEVEL)

            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        logger.addHandler(stream_handler)

        return logger
