import os
import logging
import shlex
#from Controller import export_files
from Parsers import WPScan_Parser
from GLOBALS import *
import subprocess

class WPScan_Control:
    BASE_DIR = os.getcwd()
    WPScan_BIN = BASE_DIR + '/Scanners/src/wpscan/wpscan.rb'
    ARGS = ' --no-color --no-banner -r -e {} --url {}'
    ENUMS = '[p, t]'
    OUTPUT = 'Outfiles/{}_WPScan.txt'

    def __init__(self, IP):
        self.targetIP = IP


    def start_WPScan(self):
        logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                                %(filename)s:%(funcName)s %(lineno)d %(message)s')
        logging.info('WPScan Running for {}'.format(self.targetIP))
        #wpscan_response = execute_rb(WPScan_Control.WPScan_BIN, WPScan_Control.WPScan_CMD.format(self.targetIP, WPScan_Control.WPScan_OUTPUT.format(self.targetIP)))
        WPScan_Command = shlex.split(self.WPScan_BIN + self.ARGS.format(self.ENUMS, self.targetIP))
        file_out = open(WPScan_Control.OUTPUT.format(self.targetIP), "w")   # Necessary to pipe WPScan Output; WPScan does not have built in export

        wpscan_response = subprocess.run(WPScan_Command, stdout=file_out)
        if not wpscan_response == 0:
            logging.info('WPScan finished with return code 0. Now parsing output')
            WPScan_Parser.Parse_WPScan(self.targetIP)
        else:
            os.remove(WPScan_Control.OUTPUT.format(self.targetIP))
            logging.error('WPScan finished with return code {}.'.format(wpscan_response))



