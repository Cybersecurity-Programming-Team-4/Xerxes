import ipaddress
import os
import logging
import subprocess
from Controller import export_files
from GLOBALS import *


class MasscanControl:
    def __init__(self):
        self.startIP = ipaddress.IPv4Address(IPV4_INT_START)
        self.endIP = ipaddress.IPv4Address(IPV4_INT_STOP)
        self.count = 3
        self.ports = str(PORTS.keys()).strip('dict_keys([').strip('])')

    def scheduleNextScan(self):
        sp = subprocess.run(['at', 'now + {} minutes python3 {}/Controller/main.py'.format(
            TIME_INCREMENT, BASE_DIR)])
        if sp.returncode == 0:
            logging.debug('Scheduled Next Scan: {}'.format(sp.args))
        else:
            logging.error('Scan Failed to Schedule! Args: {} Return Code: {}'.format(sp.args, sp.returncode))
    def prepNextScan(self):
        nsip = int(self.startIP) + IP_INCREMENT + 1
        neip = int(self.endIP) + IP_INCREMENT + 1
        self.count += 1
        if nsip >= IPV4_INT_STOP:
            logging.info('Masscan Complete!\n')
        elif neip > IPV4_INT_STOP and nsip < IPV4_INT_STOP:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(IPV4_INT_STOP)
        elif neip <= IPV4_INT_STOP and nsip < neip:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(neip)
            self.scheduleNextScan()
        else:
            logging.error('Unhandled case while prepping for next scan! Start IP: {} End IP: {}'.format(nsip, neip))
    def oneScan(self, subnet):
        logging.debug('Masscan running. Subnet: {}'.format(subnet))

        masscan_done = subprocess.run(['/usr/bin/pkexec', DEBUG_MASSCAN_BIN, '-c', MASSCAN_CONF,
            '-vv', '-p', self.ports, '-oX', DEBUG_XML_OUT.format(self.count), '--pcap',
            DEBUG_PCAP_OUT.format(self.count), subnet])

        if masscan_done.returncode == 0:
            logging.debug('Masscan finished with return code 0. Args: {}'.format(masscan_done.args))
        else:
            logging.error('Masscan finished with return code {}.'.format(masscan_done.returncode))

    def startMasscan(self):
        logging.info('Masscan running. Range: {} - {}'.format(str(self.startIP), str(self.endIP)))
        ofx = XML_OUT.format(self.count)
        ofp = PCAP_OUT.format(self.count)
        masscan_done = subprocess.run(['/usr/bin/pkexec', MASSCAN_BIN, '-c', MASSCAN_CONF,
             '-vv', '-p', self.ports, '-oX', ofx, '--pcap', ofp, self.startIP, self.endIP])
        if masscan_done.returncode == 0:
            logging.info('Masscan finished with return code 0.')
            self.prepNextScan()


        else:
            logging.error('Masscan finished with return code {}.'.format(masscan_done.returncode))

