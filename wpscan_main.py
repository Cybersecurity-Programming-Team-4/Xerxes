#!/usr/bin/python3

#Starts WPScan and runs it on list of addresses where the CMS_TYPE is the default value of "Unknown"
from Database_API import Xerxes_SQL
from Controller import wpscan_controller
from GLOBALS import *
def select_and_run_WPScans():
    db = Xerxes_SQL.connect_database()
    data = Xerxes_SQL.retrieve_site_entry(db, "IP_ADDRESS", "CMS_TYPE", "Unknown")
    print(data)
    for address in data:
        controller = wpscan_controller.WPScan_Control(address[0])
        controller.start_WPScan()


if __name__ == "__main__":
    logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                            %(filename)s:%(funcName)s %(lineno)d %(message)s')
    select_and_run_WPScans()