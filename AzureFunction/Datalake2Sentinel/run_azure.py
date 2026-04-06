import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from datetime import datetime, timezone

import azure.functions as func
import constants
from azure.identity._credentials.certificate import load_pem_certificate
from launch import start
from logger import Logger


def _get_certificate():
    if constants.CLIENT_CERTIFICATE:
        certificate = load_pem_certificate(constants.CLIENT_CERTIFICATE.encode())
        return {
            "thumbprint": certificate.fingerprint.hex(),
            "private_key": certificate.private_key,
        }
    return None


def main(mytimer: func.TimerRequest):
    utc_timestamp = datetime.now(timezone.utc).isoformat()

    logger = Logger._create_logger()

    if mytimer.past_due:
        logger.info("The timer is past due!")

    certificate = _get_certificate()

    logger.info("Start Datalake2Sentinel")
    try:
        # never run_as_cron for Azure Function
        start(logger, certificate=certificate, run_as_cron=False)
    finally:
        logger.info("End Datalake2Sentinel")
        logger.info("Python timer trigger function ran at %s", utc_timestamp)
