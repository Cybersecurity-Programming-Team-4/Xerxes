#!/usr/bin/python3

import logging
import subprocess
import os
import datetime
from GLOBALS import *
import xml.etree.ElementTree as ET
from Parsers import WiresharkXML

UNIVERSAL_FIELDS = {
    'eth' : ['eth.src_resolved', 'eth.src'],
    'tcp' : ['tcp.srcport'],
    'ip' : ['ip.src', 'ip.src_host']
}

IGNORE_PROTOS = {'frame', 'geninfo', 'fake-field-wrapper'}

DATA_ORDER = ('showname', 'show', 'value')

class PCAP_Parser:
    #/home/shawn/Desktop/wireshark-2.2.6/tshark -r /home/shawn/PycharmProjects/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap -2 -T pdml -R "tcp.stream==$stream" > stream-$stream.xml
    def __init__(self, pcap_file):
        self.pcapf = pcap_file
        self.xmlf = ''
        self.IP_ADDRESS = set()
        self.TCP_STREAMS = []  # Holds stream numbers
        self.banner = ''
        self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.ip_host = ''
        self.port = ''
        self.mac_unresolved = ''
        self.mac_resolved = ''

    def getStreams(self):
        try:
            proc_done = subprocess.run([TSHARK_BIN, '-r', self.pcapf, '-2', '-R', '\"not (tcp.flags.reset == 1 && tcp.flags.ack == 1)\"', '-T', 'fields', '-e', 'tcp.stream'],
                                stdout=subprocess.PIPE)
            proc_done.check_returncode()
            uniq_done = subprocess.run(['uniq'], stdin=proc_done.stdout, stdout=subprocess.PIPE)
            uniq_done.check_returncode()
            sort_done = subprocess.run(['sort', '-n'], stdin=uniq_done.stdout, stdout=subprocess.PIPE)
            sort_done.check_returncode()
            byte_arr = sort_done.stdout
            self.TCP_STREAMS = [int(x) for x in str(byte_arr, 'utf-8').split()] #Splitlines?
            return SUCCESS
        except Exception as e:
            logging.exception('Failed BASH command.', e)
            return ERROR

    def resetVariables(self):
        self.banner = ''
        self.mac_found = False
        self.ip_found = False
        self.prt_found = False
        self.ip = ''
        self.ip_host = ''
        self.port = ''
        self.mac_unresolved = ''
        self.mac_resolved = ''

    def parsep(self):
        try:
            for s in self.TCP_STREAMS:

                err = self.genXMLFromPCAP(s)
                #send file to bucket
                if err != SUCCESS:
                    raise Exception
                with open(self.xmlf) as fh:
                    WiresharkXML.parse_fh(fh, self.parsePacket)





        except Exception as e:
            logging.exception('Error while parsing XML file.', e)
            return ERROR


    def getData(self, elem):
        for trydata in DATA_ORDER:
            val = elem.get(trydata, default='')
            if val != '':
                return val
        return ''

    def parseField(self, elem):
        svc = elem.get('showname', default='')
        ext = FIELDS.get(svc)
        b = set()
        if ext[0] == '*':
            for f in elem.iter():
                if f.tag == 'field':
                    name = f.get('name', default='')
                    if name == '':

                    else:
                        data = self.getData(f)
                        if data != '':
                            b.add(data)


        else:
            for f in ext:
                pass

    def parsePacket(self, packet):

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
        elif not self.ip_found and packet.item_exists('ip.src'):
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
        elif not self.prt_found and packet.item_exists('tcp.srcport'):
            port = packet.get_items('tcp.srcport')
            for p in port:
                self.port = p.get_show()
                if self.port != '':
                    self.prt_found = True
                    break
        elif packet.get_items() in FIELDS.keys():


    def genXMLFromPCAP(self, stream):
        self.xmlf = OUT_DIR + 'xerxes-tshark-out-{}.xml'.format(datetime.datetime.now())
        proc_done = subprocess.run([TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'tcp.stream=={}'.format(stream), '-T', 'pdml', '>', self.xmlf])
        if proc_done.returncode == 0:
            logging.debug('Tshark finished with return code 0. Args: {}'.format(proc_done.args))
            return SUCCESS
        else:
            logging.error('Tshark finished with return code {}.'.format(proc_done.returncode))
            return ERROR
