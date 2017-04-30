import ipaddress
import os
import logging
import subprocess
import sys
sys.path.append('/home/shawn/Xerxes/Controller')
sys.path.append('/home/shawn/Xerxes/Parsers')
sys.path.append('/home/shawn/Xerxes')
import export_files
from GLOBALS import *
import PCAP_Parser

class MasscanControl:
    def __init__(self):
        self.startIP = ipaddress.IPv4Address(IPV4_INT_START)
        self.endIP = ipaddress.IPv4Address(IPV4_INT_START + IP_INCREMENT + 1)
        self.count = 0
        self.ports = str(PORTS.keys()).strip('dict_keys([').strip('])')
        self.PARSER = PCAP_Parser.PCAP_Parser()
        self.NO_STOP = True
        self.NO_STOP_DONE = False

    def scheduleNextScan(self):
        sp = subprocess.run(('at', 'now + {} minutes python3 {}/Controller/main.py'.format(
            TIME_INCREMENT, BASE_DIR)))
        if sp.returncode == 0:
            logging.info('Scheduled Next Scan: {}'.format(sp.args))
        else:
            logging.error('Scan Failed to Schedule! Args: {} Return Code: {}'.format(sp.args, sp.returncode))

    def prepNextScan(self):
        global CURRENT_IP_START, CURRENT_IP_END
        nsip = int(self.startIP) + IP_INCREMENT + 1
        neip = int(self.endIP) + IP_INCREMENT + 1
        self.count += 1
        if nsip >= IPV4_INT_STOP:
            logging.info('Masscan Complete!')
            self.NO_STOP_DONE = True
        elif neip > IPV4_INT_STOP and nsip < IPV4_INT_STOP:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(IPV4_INT_STOP)
            CURRENT_IP_START = str(self.startIP)
            CURRENT_IP_END = str(self.endIP)
        elif neip <= IPV4_INT_STOP and nsip < neip:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(neip)
            CURRENT_IP_START = str(self.startIP)
            CURRENT_IP_END = str(self.endIP)
            if self.NO_STOP:
                pass
            else:
                self.scheduleNextScan()
        else:
            logging.error('Unhandled case while prepping for next scan! Start IP: {} End IP: {}'.format(nsip, neip))
            self.NO_STOP_DONE = True

    #def oneScan(self, subnet):
     #   logging.info('Masscan running. Subnet: {}'.format(subnet))
#
 #       masscan_done = subprocess.run(('/usr/bin/pkexec', DEBUG_MASSCAN_BIN, '-c', MASSCAN_CONF,
  #          '-vv', '-p', self.ports, '-oX', DEBUG_XML_OUT.format(self.count), '--pcap',
   #         DEBUG_PCAP_OUT.format(self.count), subnet))
#
 #       if masscan_done.returncode == 0:
  #          logging.info('Masscan finished with return code 0. Args: {}'.format(masscan_done.args))
   #     else:
    #        logging.error('Masscan finished with return code {}.'.format(masscan_done.returncode))

    def startMasscan(self):
        logging.info('Masscan running. Range: {} - {}'.format(str(self.startIP), str(self.endIP)))
        #ofx = XML_OUT.format(self.count)
        ofp = PCAP_OUT.format(self.count)
        masscan_done = subprocess.run(('sudo', MASSCAN_BIN, '-c', MASSCAN_CONF,
            '-p', self.ports, '--pcap', ofp, self.startIP, self.endIP))
        if masscan_done.returncode == 0:
            logging.info('Masscan finished with return code 0.')
            self.prepNextScan()
        else:
            logging.error('Masscan finished with return code {}.'.format(masscan_done.returncode))

    def startMasscanNS(self):
        while not self.NO_STOP_DONE:
            logging.info('Masscan running. Range: {} - {}'.format(str(self.startIP), str(self.endIP)))
            #ofx = XML_OUT.format(self.count)
            ofp = PCAP_OUT.format(self.count)
            masscan_done = subprocess.run(('sudo', MASSCAN_BIN, '-c', MASSCAN_CONF,
                 '-p', self.ports, '--pcap', ofp, str(self.startIP), str(self.endIP)))
            if masscan_done.returncode == 0:
                logging.info('Masscan finished with return code 0.')
                self.PARSER.start(ofp)
                export_files.exportFile(ofp, 'application/octet-stream')
                self.prepNextScan()
            else:
                logging.error('Masscan finished with return code {}! Scan range {} - {} likely did not complete!'.
                              format(masscan_done.returncode, str(self.startIP), str(self.endIP)))
                export_files.exportFiles()
                #export_files.exportLogs()
                self.prepNextScan()
