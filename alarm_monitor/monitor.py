from asyncio import get_running_loop, run, sleep
from concurrent.futures import ThreadPoolExecutor
import logging
from os import environ

from click import command, option

from .facebook_msg import get_fb_user_id, send_fb_message
from .alarm import AlarmConnection


logger = logging.getLogger('alarm_monitor')
logger.setLevel(logging.INFO)


async def monitor_alarm_async(
    ip: str, port: int, facebookToken: str, alert_fb_id: str
):
    loop = get_running_loop()
    pool = ThreadPoolExecutor()

    fb_user_id = await get_fb_user_id(facebookToken)
    if not fb_user_id:
        raise RuntimeError('Could not get fb user id')
    logger.info(f'FB user id: {fb_user_id}')

    alarm_conn = AlarmConnection(ip, port)
    logger.info(f'Connected to alarm at {ip}:{port}')

    while True:
        # await loop.run_in_executor(pool, alarm_conn.query_alarm)
        alarm_conn.query_alarm()
        # alarm_messages = await loop.run_in_executor(pool, alarm_conn.receive_data)
        alarm_messages = alarm_conn.receive_data()
        if alarm_messages:
            for message in alarm_messages:
                print(message)
                # await send_fb_message(alert_fb_id, message, facebookToken)

        await sleep(5)


@command()
@option("--alarm_ip", help="IP address of alarm")
@option("--alarm_port", default=10967, help="Port of alarm")
@option("--alert_fb_id", help="FB id to send alert messages")
def monitor_alarm(alarm_ip, alarm_port, alert_fb_id):
    run(monitor_alarm_async(alarm_ip, alarm_port, environ['FACEBOOK_TOKEN'], alert_fb_id))


if __name__ == "__main__":
    logging.basicConfig()
    monitor_alarm()