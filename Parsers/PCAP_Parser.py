#!/usr/bin/python3

import logging
import subprocess
import time
import datetime
from io import StringIO
import sys
sys.path.append('/home/shawn/Xerxes/Database_API')
sys.path.append('/home/shawn/Xerxes/Controller')
sys.path.append('/home/shawn/Xerxes/Parsers')
sys.path.append('/home/shawn/Xerxes')
from GLOBALS import *
import WiresharkXML
import Xerxes_SQL
import export_files
import Masscan_Parser

#UNIVERSAL_FIELDS = {
 #   'eth' : ['eth.src_resolved', 'eth.src'],
  #  'tcp' : ['tcp.srcport'],
   # 'ip' : ['ip.src', 'ip.src_host']
#}

#IGNORE_PROTOS = {'frame', 'geninfo', 'fake-field-wrapper', 'eth', 'ip', 'tcp'}
#DATA_ORDER = ('showname', 'show', 'value')


class PCAP_Parser:
    def __init__(self):
        self.pcapf = ''
        self.xmlf = ''
        self.IP_ADDRESS = set()
        self.TCP_STREAMS = set()  # Holds stream numbers
        self.banner = StringIO()
        #self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.ip_host = ''
        self.port = ''
       # self.mac_unresolved = ''
        #self.mac_resolved = ''
        self.svc = ''
        self.DATABASE = object()

    def getStreams(self):
        try:
            proc_done = subprocess.run((TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'not (tcp.flags.reset == 1 && tcp.flags.ack == 1)', '-T', 'fields', '-e', 'tcp.stream'),
                stdout=subprocess.PIPE)
            outp = proc_done.stdout.decode().rstrip().splitlines()
            for p in outp:
                self.TCP_STREAMS.add(int(p))
            return SUCCESS
        except Exception as e:
            logging.error('Failed tshark TCP stream extraction! {}'.format(e))
            return ERROR

    def resetVariables(self):
        self.xmlf = ''
        self.banner.close()
        self.banner = StringIO()
        #self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.svc = ''
        self.ip_host = ''
        self.port = ''
        #self.mac_unresolved = ''
        #self.mac_resolved = ''

    def parseStream(self):
        try:
            for s in self.TCP_STREAMS:
                self.resetVariables()
                err = self.genXMLFromPCAP(s)
                if err != SUCCESS:
                    raise Exception('Could not generate XML from PCAP!')
                # Export XML file to bucket
                export_files.exportFile(self.xmlf, 'text/plain')
                with open(self.xmlf, 'r') as fh:
                    WiresharkXML.parse_fh(fh, self.parsePacket)
        except Exception as e:
            logging.error('Error while parsing XML file. IP: {} TCP Stream: {} {}'.format(self.ip, s, e))
            return ERROR

    def parsePacket(self, packet, protos):
        #if not self.mac_found and packet.item_exists('eth.src'):
         #   macs = packet.get_items('eth.src_resolved')
          #  for mac in macs:
           #     self.mac_resolved = mac.get_show()
            #    if self.mac_resolved != '':
             #       self.mac_found = True
              #      break
            #macsur = packet.get_items('eth.src')
            #for macur in macsur:
             #   self.mac_unresolved = macur.get_show()
              #  if self.mac_unresolved != '':
               #     self.mac_found = True
                #    break
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
                    if self.ip not in self.IP_ADDRESS:
                        self.IP_ADDRESS.add(self.ip)
                        try:
                            WHOIs_Response = Masscan_Parser.get_WHOIS(self.ip)
                            region = WHOIs_Response['asn_country_code']
                            returnedName = Masscan_Parser.getHostName(self.ip)
                            Xerxes_SQL.insert_host_entry(self.DATABASE, self.ip, returnedName, 'IPv4', region,
                                                         str(datetime.datetime.utcnow()))
                            Xerxes_SQL.insert_into_whois(self.DATABASE, self.ip, WHOIs_Response)

                        except Exception as e:
                            logging.error('Could not complete host information insertion for {} {}'.format(self.ip, e))
                            # macf = self.mac_unresolved.replace(':', '')
                            # macff = macf.upper()[:6]
                            # ven = MAC_VENDORS.get(macff, '')
                            # Xerxes_SQL.insert_device_entry(self.DATABASE, self.ip, self.mac_unresolved, ven)
                    break
        if not self.prt_found and packet.item_exists('tcp.srcport'):
            port = packet.get_items('tcp.srcport')
            for p in port:
                self.port = p.get_show()
                if self.port != '':
                    self.prt_found = True
                    break
        for p in protos:
            self.svc = p
            pitems = packet.get_items(p)
            for i in pitems:
                i.dump(self.banner)
        if len(self.banner.getvalue()) != 0:
            tempbanner = StringIO()
            tempbanner.write(XML_HEADERS)
            tempbanner.write(self.banner.getvalue())
            tempbanner.write(XML_FOOTER)
            Xerxes_SQL.insert_into_host_open_services(self.DATABASE, self.ip, self.port, self.svc, tempbanner.getvalue())
            tempbanner.close()

    def genXMLFromPCAP(self, stream):
        global XML_OUT_COUNT
        self.xmlf = OUT_DIR + 'xerxes-tshark-out-{}.xml'.format(XML_OUT_COUNT)
        XML_OUT_COUNT += 1
        with open(self.xmlf, 'w') as f:
            proc_done = subprocess.run((TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'tcp.stream=={}'.format(stream), '-T', 'pdml'), stdout=f)
        if proc_done.returncode == 0:
            logging.info('Tshark finished with return code 0. Args: {}'.format(proc_done.args))
            return SUCCESS
        else:
            logging.error('Tshark finished with return code {}.'.format(proc_done.returncode))
            return ERROR

    def checkHostsUp(self):
        try:
            proc_done = subprocess.run((TSHARK_BIN, '-r', self.pcapf, '-Y', 'tcp.flags.reset == 1 && tcp.flags.ack == 1', '-T', 'fields', '-e', 'ip.src'),
                stdout=subprocess.PIPE)
            outp = proc_done.stdout.decode().rstrip().splitlines()
            for ip in outp:
                self.IP_ADDRESS.add(ip)
            for ip in self.IP_ADDRESS:
                WHOIs_Response = Masscan_Parser.get_WHOIS(ip)
                region = WHOIs_Response['asn_country_code']
                returnedName = Masscan_Parser.getHostName(ip)

                Xerxes_SQL.insert_host_entry(self.DATABASE, ip, returnedName, 'IPv4', region,
                                             str(datetime.datetime.utcnow()))
                Xerxes_SQL.insert_into_whois(self.DATABASE, ip, WHOIs_Response)
            return SUCCESS
        except Exception as e:
            logging.error('Failed to process/insert hosts! {}'.format(e))
            return ERROR

    def start(self, pcap):
        try:
            self.DATABASE = Xerxes_SQL.connect_database()
            self.IP_ADDRESS.clear()
            self.TCP_STREAMS.clear()
            if pcap == '':
                raise FileNotFoundError('PCAP Filename is an empty string!')
            self.pcapf = pcap
            self.checkHostsUp()
            s = self.getStreams()
            if s != SUCCESS:
                raise Exception('Could not get TCP streams!')
            else:
                self.parseStream()

                self.DATABASE.close()
        except Exception as e:
            self.DATABASE.close()
            logging.error('{}'.format(e))
