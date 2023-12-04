import config as cfg

from Tapo.tapo import Tapo
from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
from datetime import datetime, timezone

import logging
from time import sleep

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('Tapo/Run')

tapo = Tapo(cfg.tapoIP, cfg.tapoUser, cfg.tapoPwd, cfg.tapoTerminalUUID)

influx = InfluxDBClient(url=cfg.influxURL, token=cfg.influxToken, org=cfg.influxOrg)
write_api = influx.write_api(write_options=SYNCHRONOUS)


try:
    while True:
        powerUsage = tapo.getCurrentPower()['result']['current_power']
        point = [{
            'measurement': cfg.influxMeasurement,
            'tags': {
                'sensorType': 'TP-Link Tapo',
                'sensorID': cfg.influxSensor
            },
            'fields': {
                'power': powerUsage
            },
            'time': datetime.now(timezone.utc).isoformat()
        }]
        write_api.write(bucket=cfg.influxBucket, org=cfg.influxOrg, record=point)

        sleep(cfg.loopDelay)
except KeyboardInterrupt:
    logger.info('Caught KeyboardInterrupt')
except Exception as e:
    logger.exception(e)
finally:
    logger.info('Execution stopped')
