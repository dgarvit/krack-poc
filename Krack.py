import os.path
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
global_log_level = INFO
COLORCODES = {
    "gray"  : "\033[0;37m",
    "green" : "\033[0;32m",
    "orange": "\033[0;33m",
    "red"   : "\033[0;31m"
}

def log(level, msg, color=None, showtime=True):
    if level < global_log_level: return
    if level == DEBUG   and color is None: color="gray"
    if level == WARNING and color is None: color="orange"
    if level == ERROR   and color is None: color="red"
    print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"


class DetectKRACK():

    def __init__ (self):
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        interface = "wlan0"  # Enter wifi interface here
        self.nic_iface = interface
        self.nic_mon = interface + "mon"
        self.apmac = scapy.arch.get_if_hwaddr(interface)
        self.sock_mon = None
        self.sock_eth = None
        self.hostapd = None
        self.hostapd_ctrl = None
        self.clients = dict()

if __name__ == '__main__':
    attack = DetectKRACK()
