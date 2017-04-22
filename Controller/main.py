#!/usr/bin/python3

import logging
import os
import pickle
from Controller import masscan_controller


BASE_DIR = os.getcwd()
LOG_DIR = BASE_DIR + '/Logs'

def runAnalysis(filename):
    pass

def main():
    logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                        %(filename)s:%(funcName)s %(lineno)d %(message)s')
    if os.path.isfile(BASE_DIR + '/Controller/pickle/xerxes_controller.pkl'):
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'rb+') as xp:
                mc_pickle = pickle.load(xp)
                mc_pickle.startMasscan()
                pickle.dump(mc_pickle, xp)

        except IOError as e:
            logging.exception('Could not open pickle file for reading/writing!')
    else:
        mc = masscan_controller.MasscanControl()
        mc.startMasscan()
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'wb') as wp:
                pickle.dump(mc, wp)
        except IOError as e:
            logging.exception('Could not open pickle file for writing!')

def test():
    logging.basicConfig(filename='/home/shawn/PycharmProjects/Xerxes/xerxes.log', format='[%(levelname)s] %(asctime)s \
                                            %(filename)s:%(funcName)s %(lineno)d %(message)s')
    mc = masscan_controller.MasscanControl()
    mc.oneScan('41.0.0.0/18')

if __name__ == '__main__':
    test()