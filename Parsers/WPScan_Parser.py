#!/usr/bin/python3
import sys
sys.path.insert(0,"..\\Database_API")
import Xerxes_SQL

def parse_plugin_scan_result(IP_Address):
    db = Xerxes_SQL.connect_database()
    with open("..\\Test_Documents\\" +IP_Address + "_WPScan.txt", 'r') as infile:
        for line in infile:
            #print(line)
            if line.rstrip('\n') == "[!] The remote website is up, but does not seem to be running WordPress.":
                db.close()
                return
            if "WordPress version" in line:
                version_line = line.rsplit()
                if version_line[3] != "can":
                    Xerxes_SQL.update_site_entry(db, IP_Address, "CMS", "WordPress " + version_line[3])
            if "WordPress theme in use: " in line:
                theme_line = line.rsplit()
                print("theme = " + theme_line[5] + " " + theme_line[7])
                Xerxes_SQL.insert_into_site_vulnerabilities(db, IP_Address, "Theme", theme_line[5] + " " + theme_line[7])
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
        db.close()

if __name__ == '__main__':
    parse_plugin_scan_result(sys.argv[1])

