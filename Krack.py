import os.path
from scapy.all import *

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
