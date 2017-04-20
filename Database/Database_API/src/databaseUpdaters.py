#!/usr/bin/python3
import SQL_Statements
import socket
import difflib
import requests
import urllib
import sys
import os
import datetime
from Naked.toolshed.shell import muterun_rb
import shutil
import json
import filecmp
import difflib

def update_local_VP(vp_file):
    # vp_file_formatted = json.loads(vp_file)
    # vp_old_formatted = json.loads(vp_old_file)
    # with open(vp_file, 'r') as new_file:
    #     new_contents = new_file.read().splitlines()
    #     new_set = set(new_contents)
    # with open(vp_old_file, 'r') as old_file:
    #     old_contents = old_file.read().splitlines()
    #     old_set = set(old_contents)
    # for diff in new_set-old_set:
    #     print(diff)
    out_file_name = "updated_plugins.csv"
    out_file = open(out_file_name, "w")
    with open(vp_file) as plugins_file:
        plugins = json.load(plugins_file)
        for plugin in plugins:
            #print(plugin)
            if plugins[plugin]['latest_version'] is not None:
                version_str = plugins[plugin]['latest_version']
            else:
                version_str = "n/a"
            for vulnerability in plugins[plugin]['vulnerabilities']:
                out_file.write(plugin + ";Plugin;WordPress;n/a;" + version_str + ";" + vulnerability['title']+"\n")
    plugins_file.close()
    out_file.close()
    db = SQL_Statements.connect_database()
    cursor = db.cursor()
    load_statement = "LOAD DATA LOCAL INFILE '" + out_file_name + "' \
    IGNORE INTO TABLE CMS_VULNERABILITIES \
    FIELDS TERMINATED BY ';' \
    LINES TERMINATED BY '\\n' \
    (EXTENSION_NAME, EXTENSION_TYPE, CMS, MIN_VERSION, MAX_VERSION, ATTACK_DESCRIPTION);"

    try:
        cursor.execute(load_statement)                      # Then update
    except:
        db.rollback()
        print("Update Error: Can't update table")
    else:
        db.commit()
        print("Updated WordPress Vulnerable Plugins")

            # except:
    #     db.rollback()

def update_local_VT():
    print("Updated WordPress Vulnerable Themes")


if __name__ == "__main__":
    # Where vp = vulnerable plugins
    # and   vt = vulnerable themes
    # TODO set prints to write to log file
    vp_need_update = False
    vt_need_update = False
    vp_file_name = "/home/logan/Desktop/wpscan/data/plugins.json"
    vp_current_file_name = "/home/logan/Desktop/wpscan/data/current_plugins.json"
    vt_file_name = "/home/logan/Desktop/wpscan/data/themes.json"
    vt_current_file_name = "/home/logan/Desktop/wpscan/data/current_themes.json"

    try:
        shutil.copyfile(vp_file_name, vp_current_file_name)
    except:
        print("Error: <" + vp_file_name + "> not found, must force update")
        vp_need_update = True
    try:
        shutil.copyfile(vt_file_name, vt_current_file_name)
    except:
        print("Error: <" + vt_file_name + "> not found, must force update")
        vt_need_update = True
    if not vp_need_update or not vt_need_update:
        response = muterun_rb("/home/logan/Desktop/wpscan/wpscan.rb --no-color --no-banner --update")
        #print(response)
        if response.exitcode != 0:
            print("Error calling WPScan Update " + str(datetime.datetime.now()))
            exit(-1)
        #os.remove(new_file_name)
        else:
            vp_need_update = not(filecmp.cmp(vp_file_name, vp_current_file_name))
            vt_need_update = not(filecmp.cmp(vt_file_name, vt_current_file_name))
    if not vp_need_update:
        update_local_VP(vp_file_name)
        print("Updating vulnerable plugins locally")
    if vt_need_update:
        update_local_VT()
        print("Updating vulnerable themes locally")