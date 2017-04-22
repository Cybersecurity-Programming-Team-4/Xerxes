#!/usr/bin/python3
import sys
#sys.path.insert(0,"..\\Database_API")
from Database_API import Xerxes_SQL
from xml.dom import minidom
import datetime
import socket
import logging

def getHostName(IPAddress):
    try:
        name = socket.gethostbyaddr(IPAddress)[0] # function returns a triple, gets the name from first element
    except:
        name = "DNS Resolution Failure"
    return name

# Parses the specified XML file generated by Masscan and stores the results in the cloud DB
def MassXMLParse(f):
    logging.basicConfig(filename="../Logs/Masscan_Information_Retrieval_{}.log".format(datetime.datetime.now()), level=logging.DEBUG)
    db = Xerxes_SQL.connect_database()     # connect to the DB via credentials
    xmldoc = minidom.parse(f)   # Parse the xml file
    hosts = xmldoc.getElementsByTagName('host') # Gets list of hosts scanned

    for host in hosts:
        # Grab the int version and convert it to human readable
        timeStr = datetime.datetime.fromtimestamp(int(host.attributes['endtime'].value)).strftime('%Y-%m-%d %H:%M:%S')
        # Grabbing rest of hot information from Masscan
        portsList = host.getElementsByTagName('port')
        address = host.getElementsByTagName('address')[0].attributes['addr'].value
        region = Xerxes_SQL.get_IP_region(db, address)
        returnedName = getHostName(address)
        addressType = host.getElementsByTagName('address')[0].attributes['addrtype'].value

        for port in portsList:
            serviceList = port.getElementsByTagName('service')
            if len(serviceList) == 0:   # For blank services
                Xerxes_SQL.insert_into_site_open_services(db, address, port.attributes['portid'].value, "None", "None")
            else:
                for service in serviceList:
                    Xerxes_SQL.insert_into_site_open_services(db, address, port.attributes['portid'].value, service.attributes['name'].value, service.attributes['banner'].value)

        # Add with just initial info
        Xerxes_SQL.insert_site_entry(db, address, returnedName, addressType, region, timeStr)
    db.close()