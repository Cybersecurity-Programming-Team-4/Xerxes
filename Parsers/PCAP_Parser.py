#!/usr/bin/python3

import logging
import subprocess
import os
import datetime
from GLOBALS import *
import xml.etree.ElementTree as ET

UNIVERSAL_FIELDS = {
    'eth' : ['eth.src_resolved', 'eth.src'],
    'tcp' : ['tcp.srcport'],
    'ip' : ['ip.src', 'ip.src_host']
}

IGNORE_PROTOS = {'frame', 'geninfo'}

class PCAP_Parser:
    #    /home/shawn/Desktop/wireshark-2.2.6/tshark -r /home/shawn/PycharmProjects/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap -2 -T pdml -R "tcp.stream==$stream" > stream-$stream.xml
    def __init__(self, pcap_file):
        self.pcapf = pcap_file
        self.xmlf = ''
        self.IP_ADDRESS = set()
        self.TCP_STREAMS = []  # Holds stream numbers

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



    def parse(self):
        try:
            for s in self.TCP_STREAMS:
                err = self.genXMLFromPCAP(s)
                if err != SUCCESS:
                    raise Exception

                protos = []
                for event, elem in ET.iterparse(self.xmlf):



        except Exception as e:
            logging.exception('Error while parsing XML file.', e)
            return ERROR



    def genXMLFromPCAP(self, stream):
        self.xmlf = OUT_DIR + 'xerxes-tshark-out-{}.xml'.format(datetime.datetime.now())
        proc_done = subprocess.run([TSHARK_BIN, '-r', self.pcapf, '-2', '-R', 'tcp.stream=={}'.format(stream), '-T', 'pdml', '>', self.xmlf])
        if proc_done.returncode == 0:
            logging.debug('Tshark finished with return code 0. Args: {}'.format(proc_done.args))
            return SUCCESS
        else:
            logging.error('Tshark finished with return code {}.'.format(proc_done.returncode))
            return ERROR
