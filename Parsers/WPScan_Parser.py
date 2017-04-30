#!/usr/bin/python3
import sys
import os
import logging
import sys
sys.path.append('/home/shawn/Xerxes/Database_API')
import Xerxes_SQL
from Parsers import Masscan_Parser
from GLOBALS import *


def Parse_WPScan(IP):
    logging.basicConfig(filename=LOG_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                            %(filename)s:%(funcName)s %(lineno)d %(message)s')
    file_name = "OutFiles/" + IP + "_WPScan.txt"
    try:
        infile = open(file_name, 'r')
    except:
        logging.debug("Specified WordPress Scan file for {} not found".format(IP))
    else:
        db = Xerxes_SQL.connect_database()
        for line in infile:
            if line.rstrip('\n') == "[!] The remote website is up, but does not seem to be running WordPress.":
                Xerxes_SQL.update_site_entry(db, IP, "CMS_TYPE", "None")
                break
            if "WordPress version" in line:
                site_name = Masscan_Parser.getHostName(IP)
                version_line = line.rsplit()
                if version_line[3] != "can":
                    Xerxes_SQL.insert_into_CMS_SITES(db, IP, site_name, "WordPress " + version_line[3])
                else:
                    Xerxes_SQL.insert_into_CMS_SITES(db, IP, site_name, "WordPress ")
            if "WordPress theme in use: " in line:
                theme_line = line.rsplit()
                Xerxes_SQL.insert_into_site_vulnerabilities(db, IP, "Theme",
                                                            theme_line[5] + " " + theme_line[7])
            if "plugins found:" in line:
                for line in infile:
                    if "Name:" in line:
                        plugin_line = line.rsplit()
                        inserted_line = plugin_line[2]
                        if len(plugin_line) > 3:  # Checks if version was found along with the name
                            inserted_line = inserted_line + " " + plugin_line[4]
                        # Lookup to determine if identified plugin is listed as vulnerable
                        if Xerxes_SQL.CMS_extension_lookup(Xerxes_SQL.connect_database(), plugin_line[2], "WordPress"):
                            Xerxes_SQL.insert_into_site_vulnerabilities(db, IP, "Plugin", inserted_line)
            Xerxes_SQL.update_scan_request(db, IP, 'Completed')
        db.close()
        os.remove(file_name)

