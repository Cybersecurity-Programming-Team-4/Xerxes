#!/usr/bin/python3
from QuadOp_SQLFunctions import *
from xml.dom import minidom
import pymysql
import multiprocessing
import time
import socket
def getHostName(IPAddress):
    try:
        name = socket.gethostbyaddr(IPAddress)[0] # function returns a triple, gets the name from first element
    except:
        name = "DNS Failed to Resolve"
    return  name


if __name__ == "__main__":
    db = pymysql.connect(endpoint, username, password, dbname)

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
        insertSiteEntry(db, address, returnedName, addressType, "NULL", openPortsStr, responseStr, "TEST_INPUT", "NULL", 0, scanTimeStr)
        print(openPortsStr)
        print(address)
        print(addressType)
        print(len(portsList))

    db.close()

#print(socket.gethostbyaddr("69.59.196.211")[0])
