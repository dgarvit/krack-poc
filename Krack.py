from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os, stat, socket, select, atexit


ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
global_log_level = INFO
HANDSHAKE_TRANSMIT_INTERVAL = 2
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


class IvCollection():
    def __init__(self):
        self.ivs = dict() # maps IV values to IvInfo objects

    def reset(self):
        self.ivs = dict()

    def track_used_iv(self, p):
        iv = dot11_get_iv(p)
        self.ivs[iv] = IvInfo(p)

    def is_iv_reused(self, p):
        """Returns True if this is an *observed* IV reuse and not just a retransmission"""
        iv = dot11_get_iv(p)
        return iv in self.ivs and self.ivs[iv].is_reused(p)

    def is_new_iv(self, p):
        """Returns True if the IV in this frame is higher than all previously observed ones"""
        iv = dot11_get_iv(p)
        if len(self.ivs) == 0: return True
        return iv > max(self.ivs.keys())


class ClientState():
    UNKNOWN, VULNERABLE, PATCHED = range(3)
    IDLE, STARTED, GOT_CANARY, FINISHED = range(4)

    def __init__(self, clientmac):
        self.mac = clientmac
        self.TK = None
        self.vuln_4way = ClientState.UNKNOWN

        self.ivs = IvCollection()
        self.pairkey_sent_time_prev_iv = None
        self.pairkey_intervals_no_iv_reuse = 0
        self.pairkey_tptk = test_tptk

    def get_encryption_key(self, hostapd_ctrl):
        if self.TK is None:
            # Clear old replies and messages from the hostapd control interface
            while hostapd_ctrl.pending():
                hostapd_ctrl.recv()
            # Contact our modified Hostapd instance to request the pairwise key
            response = hostapd_command(hostapd_ctrl, "GET_TK " + self.mac)
            if not "FAIL" in response:
                self.TK = response.strip().decode("hex")
        return self.TK

    def decrypt(self, p, hostapd_ctrl):
        payload = get_ccmp_payload(p)
        llcsnap, packet = payload[:8], payload[8:]

        if payload.startswith("\xAA\xAA\x03\x00\x00\x00"):
            # On some kernels, the virtual interface associated to the real AP interface will return
            # frames where the payload is already decrypted (this happens when hardware decryption is
            # used). So if the payload seems decrypted, just extract the full plaintext from the frame.
            plaintext = payload
        else:
            key       = self.get_encryption_key(hostapd_ctrl)
            plaintext = decrypt_ccmp(p, key)

            # If it still fails, try an all-zero key
            if not plaintext.startswith("\xAA\xAA\x03\x00\x00\x00"):
                plaintext = decrypt_ccmp(p, "\x00" * 16)

        return plaintext

    def track_used_iv(self, p):
        return self.ivs.track_used_iv(p)

    def is_iv_reused(self, p):
        return self.ivs.is_iv_reused(p)

    def check_pairwise_reinstall(self, p):
        """Inspect whether the IV is reused, or whether the client seem to be patched"""

        # If this is gaurenteed IV reuse (and not just a benign retransmission), mark the client as vulnerable
        if self.ivs.is_iv_reused(p):
            if self.vuln_4way != ClientState.VULNERABLE:
                iv = dot11_get_iv(p)
                seq = dot11_get_seqnum(p)
                log(INFO, ("%s: IV reuse detected (IV=%d, seq=%d). " +
                    "Client is vulnerable to pairwise key reinstallations in the 4-way handshake!") % (self.mac, iv, seq), color="green")
            self.vuln_4way = ClientState.VULNERABLE

        # If it's a higher IV than all previous ones, try to check if the client seems patched
        elif self.vuln_4way == ClientState.UNKNOWN and self.ivs.is_new_iv(p):
            # Save how many intervals we received a data packet without IV reset. Use twice the
            # transmission interval of message 3, in case one message 3 is lost due to noise.
            if self.pairkey_sent_time_prev_iv is None:
                self.pairkey_sent_time_prev_iv = p.time
            elif self.pairkey_sent_time_prev_iv + 2 * HANDSHAKE_TRANSMIT_INTERVAL + 1 <= p.time:
                self.pairkey_intervals_no_iv_reuse += 1
                self.pairkey_sent_time_prev_iv = p.time
                log(DEBUG, "%s: no pairwise IV resets seem to have occured for one interval" % self.mac)

            # If during several intervals all IV reset attempts failed, the client is likely patched.
            # We wait for enough such intervals to occur, to avoid getting a wrong result.
            if self.pairkey_intervals_no_iv_reuse >= 5 and self.vuln_4way == ClientState.UNKNOWN:
                self.vuln_4way = ClientState.PATCHED

                # Be sure to clarify *which* type of attack failed (to remind user to test others attacks as well)
                msg = "%s: client DOESN'T seem vulnerable to pairwise key reinstallation in the 4-way handshake"
                if self.pairkey_tptk == KRAckAttackClient.TPTK_NONE:
                    msg += " (using standard attack)"
                elif self.pairkey_tptk == KRAckAttackClient.TPTK_REPLAY:
                    msg += " (using TPTK attack)"
                elif self.pairkey_tptk == KRAckAttackClient.TPTK_RAND:
                    msg += " (using TPTK-RAND attack)"
                log(INFO, (msg + ".") % self.mac, color="green")

    def mark_allzero_key(self, p):
        if self.vuln_4way != ClientState.VULNERABLE:
            iv = dot11_get_iv(p)
            seq = dot11_get_seqnum(p)
            log(INFO, ("%s: usage of all-zero key detected (IV=%d, seq=%d). " +
                "Client is vulnerable to (re)installation of an all-zero key in the 4-way handshake!") % (self.mac, iv, seq), color="green")
            log(WARNING, "%s: !!! Other tests are unreliable due to all-zero key usage, please fix this first !!!" % self.mac)
        self.vuln_4way = ClientState.VULNERABLE


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

        """self.dhcp = DHCP_sock(sock=self.sock_eth,
                        domain='krackattack.com',
                        pool=Net('192.168.100.0/24'),
                        network='192.168.100.0/24',
                        gw='192.168.100.254',
                        renewal_time=600, lease_time=3600)
        # Configure gateway IP: reply to ARP and ping requests
        subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

        self.group_ip = self.dhcp.pool.pop()
        self.group_arp = ARP_sock(sock=self.sock_eth, IP_addr=self.group_ip, ARP_addr=self.apmac)"""

        log(STATUS, "Ready. Connect to this Access Point to start the tests.", color="green")

        # Monitor both the normal interface and virtual monitor interface of the AP
        self.next_arp = time.time() + 1
        while True:
            sel = select.select([self.sock_mon, self.sock_eth], [], [], 1)
            if self.sock_mon in sel[0]:
                self.handle_mon()
            if self.sock_eth in sel[0]:
                self.handle_eth()

            # Periodically send the replayed broadcast ARP requests to test for group key reinstallations
            """if time.time() > self.next_arp:
                self.next_arp = time.time() + HANDSHAKE_TRANSMIT_INTERVAL
                for client in self.clients.values():
                    # Also keep injecting to PATCHED clients (just to be sure they keep rejecting replayed frames)
                    if client.vuln_group != ClientState.VULNERABLE and client.mac in self.dhcp.leases:
                        clientip = self.dhcp.leases[client.mac]
                        client.groupkey_track_request()
                        log(INFO, "%s: sending broadcast ARP to %s from %s" % (client.mac, clientip, self.group_ip))

                        request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=self.apmac, psrc=self.group_ip, pdst=clientip)
                        self.sock_eth.send(request)"""

    def handle_mon (self):
        p = self.sock_mon.recv()
        if p == None: return
        if p.type == 1: return

        if (p.FCfield & 2) != 0:
            clientmac, apmac = (p.addr1, p.addr2)
        else:
            clientmac, apmac = (p.addr2, p.addr1)

        if apmac != self.apmac:
            return None

        elif p.addr1 == self.apmac and Dot11WEP in p:
            if not clientmac in self.clients:
                self.clients[clientmac] = ClientState(clientmac)
            client = self.clients[clientmac]

            iv = dot11_get_iv(p)
            log(DEBUG, "%s: transmitted data using IV=%d (seq=%d)" % (clientmac, iv, dot11_get_seqnum(p)))

            if decrypt_ccmp(p, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00"):
                client.mark_allzero_key(p)
            client.check_pairwise_reinstall(p)
            if client.is_iv_reused(p):
                self.handle_replay(p)
            client.track_used_iv(p)


    def handle_eth (self):
        pass

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()
        if self.sock_mon:
            self.sock_mon.close()
        if self.sock_eth:
            self.sock_eth.close()



def cleanup():
    attack.stop()

if __name__ == '__main__':
    attack = DetectKRACK()
    atexit.register(cleanup)
    attack.run()
