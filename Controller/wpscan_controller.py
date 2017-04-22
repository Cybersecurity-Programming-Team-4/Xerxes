import ipaddress
from Naked.toolshed.shell import execute_rb
import os
import logging
import sys
#sys.path.insert(0,"../Parsers")
from Parsers import WPScan_Parser
import subprocess

class WPScan_Control:
    BASE_DIR = os.getcwd()
    WPScan_BIN = '../Scanners/src/wpscan/wpscan.rb'
    WPScan_CMD = ' --no-color --no-banner --follow-redsadfdirection -r  -e[p, t] --url {} > {}'
    WPScan_OUTPUT = '../Test_Documents/{}_WPScan.txt'

    def __init__(self, IP):
        self.targetIP = IP


    def start_WPScan(self):
        logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                                       %(filename)s:%(funcName)s %(lineno)d %(message)s')
        logging.info('WPScan Running for {}'.format(self.targetIP))
        wpscan_response = execute_rb(WPScan_Control.WPScan_BIN + WPScan_Control.WPScan_CMD.format(self.targetIP, WPScan_Control.WPScan_OUTPUT.format(self.targetIP)))
        print(wpscan_response.)
        if wpscan_response == 0:
            logging.info('WPScan finished with return code 0. Now parsing output')
            WPScan_Parser.WPScan_Parser(self.targetIP).Parse_WPScan()
        else:
            logging.error('WPScan finished with return code {}.'.format(wpscan_response))

# if __name__ == "__main__":
#     print("running")
#     newcontrol = WPScan_Control("127.0.0.1")
#     print(newcontrol.targetIP)
#     newcontrol.start_WPScan()

