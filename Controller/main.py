import logging
import os
import pickle
from .masscan_controller import MasscanControl



def runAnalysis(filename):
    pass

def main():
    logging.basicConfig(filename='/var/log/xerxes.log', format='[%(levelname)s] %(asctime)s \
                                        %(filename)s:%(funcName)s %(lineno)d %(message)s')
    if os.path.isfile(os.getcwd() + '/pickle/xerxes_controller.pkl'):
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'rb+') as xp:
                mc_pickle = pickle.load(xp)
                mc_pickle.startMasscan()
                pickle.dump(mc_pickle, xp)

        except IOError as e:
            logging.exception('Could not open pickle file for reading!')
    else:
        mc = MasscanControl()
        mc.startMasscan()
        try:
            with open('./pickle/xerxes-masscan-controller.pkl', 'wb') as wp:
                pickle.dump(mc, wp)
        except IOError as e:
            logging.exception('Could not open pickle file for reading!')



if __name__ == '__main__':
    main()