#!/usr/bin/python3

import logging
import subprocess
import time
from io import TextIOWrapper, BufferedIOBase, BytesIO, TextIOBase, StringIO
from GLOBALS import *
from Parsers import WiresharkXML
#from Database_API import Xerxes_SQL

UNIVERSAL_FIELDS = {
    'eth' : ['eth.src_resolved', 'eth.src'],
    'tcp' : ['tcp.srcport'],
    'ip' : ['ip.src', 'ip.src_host']
}

IGNORE_PROTOS = {'frame', 'geninfo', 'fake-field-wrapper', 'eth', 'ip', 'tcp'}
DATA_ORDER = ('showname', 'show', 'value')

class PCAP_Parser:
    #/home/shawn/Desktop/wireshark-2.2.6/tshark -r /home/shawn/PycharmProjects/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap -2 -T pdml -R "tcp.stream==$stream" > stream-$stream.xml
    def __init__(self, pcap_file):
        self.pcapf = pcap_file
        self.xmlf = ''
        self.IP_ADDRESS = set()
        self.TCP_STREAMS = set()  # Holds stream numbers
        self.banner = StringIO()
        self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.ip_host = ''
        self.port = ''
        self.mac_unresolved = ''
        self.mac_resolved = ''
        #self.DATABASE = Xerxes_SQL.connect_database()

    def getStreams(self):
        try:
            proc_done = subprocess.run((TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'not (tcp.flags.reset == 1 && tcp.flags.ack == 1)', '-T', 'fields', '-e', 'tcp.stream'),
                stdout=subprocess.PIPE)
            outp = proc_done.stdout.decode().rstrip().splitlines()
            for p in outp:
                print(int(p))
                self.TCP_STREAMS.add(int(p))
            return SUCCESS
        except Exception as e:
            logging.exception('Failed BASH command!', exc_info=e)
            return ERROR

    def resetVariables(self):
        self.banner.close()
        self.banner = StringIO()
        self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.ip_host = ''
        self.port = ''
        self.mac_unresolved = ''
        self.mac_resolved = ''

    def parseStream(self):
        try:
            for s in self.TCP_STREAMS:
                self.resetVariables()
                err = self.genXMLFromPCAP(s)

                if err != SUCCESS:
                    raise Exception
                with open(self.xmlf) as fh:
                    WiresharkXML.parse_fh(fh, self.parsePacket)
                print(self.ip, self.ip_host, self.port, self.mac_resolved, self.mac_unresolved)
                if self.ip != '':
                    if self.ip not in self.IP_ADDRESS:
                        self.IP_ADDRESS.add(self.ip)
                        macf = self.mac_unresolved.replace(':', '')
                        macff = macf.upper()[:6]
                        ven = MAC_VENDORS.get(macff, '')
                        print(ven)

        except Exception as e:
            logging.exception('Error while parsing XML file. IP: {} TCP Stream: {}'.format(self.ip, s), exc_info=e)
            return ERROR

    def parsePacket(self, packet, protos):
        if not self.mac_found and packet.item_exists('eth.src'):
            macs = packet.get_items('eth.src_resolved')
            for mac in macs:
                self.mac_resolved = mac.get_show()
                if self.mac_resolved != '':
                    self.mac_found = True
                    break
            macsur = packet.get_items('eth.src')
            for macur in macsur:
                self.mac_unresolved = macur.get_show()
                if self.mac_unresolved != '':
                    self.mac_found = True
                    break
        if not self.ip_found and packet.item_exists('ip.src'):
            ipsh = packet.get_items('ip.src_host')
            for sh in ipsh:
                self.ip_host = sh.get_show()
                if self.ip_host != '':
                    self.ip_found = True
                    break
            ips = packet.get_items('ip.src')
            for s in ips:
                self.ip = s.get_show()
                if self.ip != '':
                    self.ip_found = True
                    break
        if not self.prt_found and packet.item_exists('tcp.srcport'):
            port = packet.get_items('tcp.srcport')
            for p in port:
                self.port = p.get_show()
                if self.port != '':
                    self.prt_found = True
                    break
        for p in protos:
            pitems = packet.get_items(p)
            for i in pitems:
                i.dump(self.banner)
            print(str(self.banner.getvalue()))

    def genXMLFromPCAP(self, stream):
        self.xmlf = OUT_DIR + 'xerxes-tshark-out-{}.xml'.format(str(time.time()).replace('.', ''))
        with open(self.xmlf, 'w') as f:
            proc_done = subprocess.run((TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'tcp.stream=={}'.format(stream), '-T', 'pdml'), stdout=f)
        if proc_done.returncode == 0:
            logging.debug('Tshark finished with return code 0. Args: {}'.format(proc_done.args))
            return SUCCESS
        else:
            logging.error('Tshark finished with return code {}.'.format(proc_done.returncode))
            return ERROR

    def start(self):
        s = self.getStreams()
        if s != SUCCESS:
            print('Error!')
        else:
            self.parseStream()

def test():
    a = PCAP_Parser(pcap_file='/home/shawn/Workspace/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap')
    a.start()

test()