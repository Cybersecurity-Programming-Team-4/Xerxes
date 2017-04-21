#!/usr/bin/python3
import pymysql
import Xerxes_SQL
#import scrape
import sys
import re

def parse_plugin_scan_result(IP_Address):
    db = Xerxes_SQL.connect_database()
    version_regex = "WordPress version"
    with open("testfiles\\prayWPScan.txt", 'r') as infile:
        for line in infile:
            #print(line)
            if line.rstrip('\n') == "[!] The remote website is up, but does not seem to be running WordPress.":
                print("not wordpress")
                db.close()
                return
            if "WordPress version" in line:
                version_line = line.rsplit()
                if version_line[3] != "can":
                    print(version_line)
                    print("wordpress version = " + version_line[3])
                    Xerxes_SQL.updateSiteEntry(db, IP_Address, "CMS", "WordPress " + version_line[3])
                #return
            if "WordPress theme in use: " in line:
                theme_line = line.rsplit()
                print("theme = " + theme_line[5] + " " + theme_line[7])
                Xerxes_SQL.insert_into_site_vulnerabilities(db, IP_Address, "Theme", theme_line[5] + " " + theme_line[7])
                #return
            if "plugins found:" in line:
                for line in infile:
                    if "Name:" in line:
                        plugin_line = line.rsplit()
                        inserted_line = plugin_line[2]
                        if len(plugin_line) > 3:    # Checks if version was found along with the name
                            inserted_line = inserted_line + " " + plugin_line[4]
                        print(inserted_line)
                        # Lookup to determine if identified plugin is listed as vulnerable
                        if Xerxes_SQL.CMS_extension_lookup(Xerxes_SQL.connect_database(), plugin_line[2], "WordPress"):
                            Xerxes_SQL.insert_into_site_vulnerabilities(db, IP_Address, "Plugin", inserted_line)
                        #SQL_Statements.insert_into_site_vulnerabilities(db, IP_Address, "Plugin", inserted_line)
        db.close()
        # db = SQL_Statements.connect_database()
        # at_plugins = False
        # for line in infile:
        #     if "WordPress version" in line:
        #         cms_str =
        # if header_str.find("Following redirection") == True:
        #     print("found redirection, stripping it")

if __name__ == '__main__':  # to test whether the script is being run on its own, meaning the Python interpreter has assigned main to its name
    parse_plugin_scan_result(192)#sys.argv[1])
    #db = SQL_Statements.connect_database()



else:
    print("imposdafsfsdfsdn run directly")  # or if it was imported, don't run anything..
