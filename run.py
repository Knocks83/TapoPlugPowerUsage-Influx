import config as cfg
from Tapo.tapo import Tapo
from time import sleep

tapo = Tapo(cfg.tapoIP, cfg.tapoUser, cfg.tapoPwd, cfg.tapoTerminalUUID)


tapo.getEnergyData()

#while True:
#    sleep(cfg.loopDelay)

