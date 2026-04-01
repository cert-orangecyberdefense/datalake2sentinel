from datetime import datetime, timezone
import azure.functions as func
from azure.identity._credentials.certificate import load_pem_certificate
from .logger import Logger
from .launch import main as pmain
from .constants import CLIENT_CERTIFICATE


def _get_certificate():
    if CLIENT_CERTIFICATE:
        certificate = load_pem_certificate(CLIENT_CERTIFICATE.encode())
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
    pmain(logger, certificate)  # never run_as_cron for Azure Function
    logger.info("End Datalake2Sentinel")
    logger.info("Python timer trigger function ran at %s", utc_timestamp)
