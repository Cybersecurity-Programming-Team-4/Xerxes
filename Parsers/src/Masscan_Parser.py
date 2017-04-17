#!/usr/bin/python3
from SQL_Statements import *
from xml.dom import minidom
import pymysql
import multiprocessing
import time
import socket

def getHostName(IPAddress):
    try:
        name = socket.gethostbyaddr(IPAddress)[0] # function returns a triple, gets the name from first element
    except:
        name = "DNS Resolution Failure"
    return  name

def check_for_CMS(IP_address, file_name):
    return 0


# Function to parse the XML file generated by Masscan and stores the results in the cloud DB
def store_scan_results(file_name):
    db = connect_database()     # connect to the DB via credentials

    xmldoc = minidom.parse(file_name)   # Parse the xml file
    hosts = xmldoc.getElementsByTagName('host') # Gets list of hosts scanned

    # Grabs finish time of the completed scan by Masscan
    scanTimeStr = xmldoc.getElementsByTagName('finished')[0].attributes['timestr'].value

    for host in hosts:
        portsList = host.getElementsByTagName('port')
        address = host.getElementsByTagName('address')[0].attributes['addr'].value
        region = get_IP_region(db, address)
        name = ""
        responseStr = ""
        returnedName = getHostName(address)
        addressType = host.getElementsByTagName('address')[0].attributes['addrtype'].value
        openPortsStr = ""
        for port in portsList:
            insertOpenPort(db, address, port.attributes['portid'].value)
            openPortsStr = openPortsStr + port.attributes['portid'].value + ", "
            statesList = port.getElementsByTagName('state')
            for state in statesList:
                responseStr = responseStr + state.attributes['reason'].value + ", "
        insertSiteEntry(db, address, returnedName, addressType, region, openPortsStr, responseStr, "TEST_INPUT", "NULL", 0, scanTimeStr)

    db.close()

if __name__ == "__main__":
    file_name = 'parse_text.xml'

    store_scan_results(file_name)
    # with open("DatabaseInfo.txt") as f:
    #     content = f.readlines()
    # # you may also want to remove whitespace characters like `\n` at the end of each line
    # content = [x.strip() for x in content]
    #
    # db = pymysql.connect(content[0], content[1], content[2], content[3])