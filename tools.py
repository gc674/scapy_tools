import sys
import re
import scapy.all as scapy
import subprocess


class osfinder:
    'Common base class for getting the os type'
    def __init__(self):
        self.os_type = sys.platform
        self.var = 'blabla'

    def is_linux(self):
        if (self.os_type == "linux"):
            return True

    def is_windows(self):
        if (self.os_type == "win32"):
            return True


class arptable:
    'Class used to return the arp table of the network or for an ip'
    def __init__(self, ip_addr):
        # ip_addr ex: "192.168.1.1" or "192.168.1.0/24"
        self.arplist = []
        self.ip_addr = ip_addr

    def get_arp_table(self):
        result = scapy.arping(self.ip_addr, verbose=False)[0]
        for element in result:
            client_reply = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            self.arplist.append(client_reply)


class regexfilter:
    'Class used to return specific strings patterns depending on operating system'
    def __init__(self, text):
        self.text = text
        self.match = None
        self.windows_mac = r'(\w{2}-){5}\w{2}'
        self.linux_mac = r'(\w{2}:){5}\w{2}'
        self.ip = r'\d*\.\d*\.\d*\.\d*'

    def search(self, pattern):
        'search and return found match'
        self.match = re.search(pattern, self.text).group()


class sendcommand:
    'Class used to send a command and return output'
    def __init__(self, command):
        self.command = command
        self.reply = []

    def get_answer(self):
        self.reply = subprocess.check_output(self.command).decode("UTF-8").splitlines()
