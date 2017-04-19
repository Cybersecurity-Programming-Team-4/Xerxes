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
from Naked.toolshed.shell import execute_rb
import shutil
import json
import filecmp
import difflib

def update_local_VP(vp_file, vp_old_file):
    vp_file_formatted = json.loads(vp_file)
    vp_old_formatted = json.loads(vp_old_file)
    with open(vp_file, 'r') as new_file:
        new_contents = new_file.read().splitlines()
        new_set = set(new_contents)
    with open(vp_old_file, 'r') as old_file:
        old_contents = old_file.read().splitlines()
        old_set = set(old_contents)
    for diff in new_set-old_set:
        print(diff)
    #db = SQL_Statements.connect_database()

    print("in necessary update")

def update_local_VT():
    print("in necessary update")


if __name__ == "__main__":
    # Where vp = vulnerable plugins
    # and   vt = vulnerable themes

    vp_file = "difftest1.txt"
    vp_old_file = "difftest2.txt"
    with open(vp_file, 'r') as new_file:
        new_contents = new_file.read().splitlines()
        new_set = set(new_contents)
    with open(vp_old_file, 'r') as old_file:
        old_contents = old_file.read().splitlines()
        old_set = set(old_contents)
    for diff in new_set-old_set:
        print(diff)

    # vp_need_update = False
    # vt_need_update = False
    # vp_file_name = "/home/logan/Desktop/wpscan/data/plugins.json"
    # vp_current_file_name = "/home/logan/Desktop/wpscan/data/current_plugins.json"
    # vt_file_name = "/home/logan/Desktop/wpscan/data/themes.json"
    # vt_current_file_name = "/home/logan/Desktop/wpscan/data/current_themes.json"
    #
    # try:
    #     shutil.copyfile(vp_file_name, vp_current_file_name)
    # except:
    #     print("Error: <" + vp_file_name + "> not found, must force update")
    #     vp_need_update = True
    # try:
    #     shutil.copyfile(vt_file_name, vt_current_file_name)
    # except:
    #     print("Error: <" + vt_file_name + "> not found, must force update")
    #     vt_need_update = True
    # if not vp_need_update or not vt_need_update:
    #     response = muterun_rb("/home/logan/Desktop/wpscan/wpscan.rb --no-color --no-banner --update")
    #     #print(response)
    #     if response.exitcode != 0:
    #         print("Error calling WPScan Update " + str(datetime.datetime.now()))
    #         exit(-1)
    #     #os.remove(new_file_name)
    #     else:
    #         vp_need_update = not(filecmp.cmp(vp_file_name, vp_current_file_name))
    #         vt_need_update = not(filecmp.cmp(vt_file_name, vt_current_file_name))
    # if vp_need_update:
    #     update_local_VP(vp_file_name, vp_current_file_name)
    #     print("Updating vulnerable plugins locally")
    # if vt_need_update:
    #     update_local_VT()
    #     print("Updating vulnerable themes locally")
