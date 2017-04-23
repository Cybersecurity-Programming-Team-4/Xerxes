#!/usr/bin/python3
import sys
import os
import logging
#sys.path.insert(0,"..\\Database_API")
from Database_API import Xerxes_SQL



def Parse_WPScan(IP):
    logging.basicConfig(filename="../Logs/WPScan_Parsing.log", level=logging.DEBUG)
    file_name = "../Test_Documents/" + IP + "_WPScan.txt"
    print(file_name)
    try:
        infile = open(file_name, 'r')
    except:
        logging.debug("Specified WordPress Scan file for {} not found".format(IP))
    else:
        db = Xerxes_SQL.connect_database()
        for line in infile:
            if line.rstrip('\n') == "[!] The remote website is up, but does not seem to be running WordPress.":
                db.close()
                exit(0)
            if "WordPress version" in line:
                version_line = line.rsplit()
                if version_line[3] != "can":
                    Xerxes_SQL.update_site_entry(db, IP, "CMS", "WordPress " + version_line[3])
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
        db.close()
        os.remove(file_name)

