from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os, stat, socket, select, atexit


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


counter = 0
class Ctrl:
    def __init__(self, path, port=9877):
        global counter
        self.started = False
        self.attached = False
        self.path = path
        self.port = port

        try:
            mode = os.stat(path).st_mode
            if stat.S_ISSOCK(mode):
                self.udp = False
            else:
                self.udp = True
        except:
            self.udp = True

        if not self.udp:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.dest = path
            self.local = "/tmp/wpa_ctrl_" + str(os.getpid()) + '-' + str(counter)
            counter += 1
            self.s.bind(self.local)
            try:
                self.s.connect(self.dest)
            except Exception, e:
                self.s.close()
                os.unlink(self.local)
                raise
        else:
            try:
                self.s = None
                ai_list = socket.getaddrinfo(path, port, socket.AF_INET,
                                             socket.SOCK_DGRAM)
                for af, socktype, proto, cn, sockaddr in ai_list:
                    self.sockaddr = sockaddr
                    break
                self.s = socket.socket(af, socktype)
                self.s.settimeout(5)
                self.s.sendto("GET_COOKIE", sockaddr)
                reply, server = self.s.recvfrom(4096)
                self.cookie = reply
                self.port = port
            except:
                print "connect exception ", path, str(port)
                if self.s != None:
                    self.s.close()
                raise
        self.started = True

    def __del__(self):
        self.close()

    def close(self):
        if self.attached:
            try:
                self.detach()
            except Exception, e:
                # Need to ignore this allow the socket to be closed
                self.attached = False
                pass
        if self.started:
            self.s.close()
            if not self.udp:
                os.unlink(self.local)
            self.started = False

    def request(self, cmd, timeout=10):
        if self.udp:
            self.s.sendto(self.cookie + cmd, self.sockaddr)
        else:
            self.s.send(cmd)
        [r, w, e] = select.select([self.s], [], [], timeout)
        if r:
            return self.s.recv(4096)
        raise Exception("Timeout on waiting response")

    def attach(self):
        if self.attached:
            return None
        res = self.request("ATTACH")
        if "OK" in res:
            self.attached = True
            return None
        raise Exception("ATTACH failed")

    def detach(self):
        if not self.attached:
            return None
        while self.pending():
            ev = self.recv()
        res = self.request("DETACH")
        if "FAIL" not in res:
            self.attached = False
            return None
        raise Exception("DETACH failed")

    def terminate(self):
        if self.attached:
            try:
                self.detach()
            except Exception, e:
                # Need to ignore this to allow the socket to be closed
                self.attached = False
        self.request("TERMINATE")
        self.close()

    def pending(self, timeout=0):
        [r, w, e] = select.select([self.s], [], [], timeout)
        if r:
            return True
        return False

    def recv(self):
        res = self.s.recv(4096)
        return res


#### Packet Processing Functions ####

class MitmSocket(L2Socket):
    def __init__(self, **kwargs):
        super(MitmSocket, self).__init__(**kwargs)

    def send(self, p):
        # Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
        p[Dot11].FCfield |= 0x20
        L2Socket.send(self, RadioTap()/p)

    def _strip_fcs(self, p):
        # Scapy can't handle the optional Frame Check Sequence (FCS) field automatically
        if p[RadioTap].present & 2 != 0:
            rawframe = str(p[RadioTap])
            pos = 8
            while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4

            # If the TSFT field is present, it must be 8-bytes aligned
            if p[RadioTap].present & 1 != 0:
                pos += (8 - (pos % 8))
                pos += 8

            # Remove FCS if present
            if ord(rawframe[pos]) & 0x10 != 0:
                return Dot11(str(p[Dot11])[:-4])

        return p[Dot11]

    def recv(self, x=MTU):
        p = L2Socket.recv(self, x)
        if p == None or not Dot11 in p: return None

        # Hack: ignore frames that we just injected and are echoed back by the kernel
        if p[Dot11].FCfield & 0x20 != 0:
            return None

        # Strip the FCS if present, and drop the RadioTap header
        return self._strip_fcs(p)

    def close(self):
        super(MitmSocket, self).close()


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

    def configure_interfaces(self):
        log(STATUS, "Note: disable Wi-Fi in network manager & disable hardware encryption. Both may interfere with this script.")
        subprocess.check_output(["rfkill", "unblock", "wifi"])
        subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])
        subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
        time.sleep(0.5)
        subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
        subprocess.check_output(["ifconfig", self.nic_mon, "up"])

    def run (self):
        self.configure_interfaces()
        log(STATUS, "Starting hostapd")
        try:
            self.hostapd = subprocess.Popen([
                os.path.join(self.script_path, "hostapd/hostapd"),
                os.path.join(self.script_path, "hostapd/hostapd.conf")
            ])
        except:
            if not os.path.exists("hostapd/hostapd"):
                log(ERROR, "hostapd not found.")
            raise
        time.sleep(1)

        try:
            self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_iface)
            self.hostapd_ctrl.attach()
        except:
            log(ERROR, "It seems hostapd did not start properly.")
            log(ERROR, "Did you disable Wi-Fi in the network manager?")
            raise

        self.sock_mon = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)
        self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()


def cleanup():
    attack.stop()

if __name__ == '__main__':
    attack = DetectKRACK()
    atexit.register(cleanup)
    attack.run()
