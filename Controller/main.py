#!/usr/bin/python3

import google.cloud.logging
import logging
import pickle
from Controller import masscan_controller
from GLOBALS import *

def main_nc():
    logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                        %(filename)s:%(funcName)s %(lineno)d %(message)s')

    client = google.cloud.logging.Client(PROJECT_ID)
    # Attaches a Google Stackdriver logging handler to the root logger
    client.setup_logging(logging.INFO)

    if os.path.isfile(BASE_DIR + '/Controller/pickle/xerxes_controller.pkl'):
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'rb+') as xp:
                mc_pickle = pickle.load(xp)
                mc_pickle.startMasscan()
                pickle.dump(mc_pickle, xp)

        except IOError as e:
            logging.exception('Could not open pickle file for reading/writing!', e)
    else:
        mc = masscan_controller.MasscanControl()
        mc.startMasscan()
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'wb') as wp:
                pickle.dump(mc, wp)
        except IOError as e:
            logging.exception('Could not open pickle file for writing!', e)

def main_c():
    logConfig()
    mc = masscan_controller.MasscanControl()
    mc.startMasscanNS()

if __name__ == 'main':
    main_c()