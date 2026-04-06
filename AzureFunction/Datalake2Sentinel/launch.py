import constants
import exceptions as exc
from apscheduler.schedulers.background import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from Datalake2Sentinel import Datalake2Sentinel


def start(logger, certificate=None, run_as_cron: bool = False):
    try:
        datalake2Sentinel = Datalake2Sentinel(logger, certificate)
    except exc.DatalakeError as e:
        logger.error(str(e))
        raise SystemExit(1)

    if run_as_cron:
        schedule_run(datalake2Sentinel.uploadIndicatorsToSentinel, constants.TRIGGER_SCHEDULE)
    else:
        datalake2Sentinel.uploadIndicatorsToSentinel()


def schedule_run(func, cron, *args, **kwargs):
    """Schedule a function with a cron schedule.

    Optionally, you can pass arguments to the function using args and kwargs.
    """
    scheduler = BlockingScheduler()
    scheduler.add_job(
        func,
        trigger=CronTrigger.from_crontab(cron),
        args=args,
        kwargs=kwargs,
    )
    scheduler.start()
