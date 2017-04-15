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




def check_for_CMS(IP_address):
    return 0

if __name__ == "__main__":
    # with open("DatabaseInfo.txt") as f:
    #     content = f.readlines()
    # # you may also want to remove whitespace characters like `\n` at the end of each line
    # content = [x.strip() for x in content]
    #
    # db = pymysql.connect(content[0], content[1], content[2], content[3])
    db = connect_database()

    xmldoc = minidom.parse('parse_test.xml')
    prettyTree = xmldoc.toprettyxml()
    print(prettyTree)
    hosts = xmldoc.getElementsByTagName('host')
    print(len(hosts))
    scanTimeStr = xmldoc.getElementsByTagName('finished')[0].attributes['timestr'].value
    print(scanTimeStr)

    for host in hosts:
        portsList = host.getElementsByTagName('port')
        address = host.getElementsByTagName('address')[0].attributes['addr'].value
        region = get_IP_geolocation(db, address)
        print(region)
        name = ""
        responseStr = ""
        returnedName = getHostName(address)
        print(returnedName)
        addressType = host.getElementsByTagName('address')[0].attributes['addrtype'].value
        openPortsStr = ""
        for port in portsList:
            insertOpenPort(db, address, port.attributes['portid'].value)
            openPortsStr = openPortsStr + port.attributes['portid'].value + ", "
            statesList = port.getElementsByTagName('state')
            for state in statesList:
                responseStr = responseStr + state.attributes['reason'].value + ", "
        #insertSiteEntry(db, address, returnedName, addressType, "NULL", openPortsStr, responseStr, "TEST_INPUT", "NULL", 0, scanTimeStr)
        print(openPortsStr)
        print(address)
        print(addressType)
        print(len(portsList))

    db.close()

#print(socket.gethostbyaddr("69.59.196.211")[0])
