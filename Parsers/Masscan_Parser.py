#!/usr/bin/python3
import sys
#sys.path.insert(0,"..\\Database_API")
#from Controller import export_files
from Database_API import Xerxes_SQL
from xml.dom import minidom
import datetime
import socket
import logging
from ipwhois import IPWhois

def get_WHOIS(IPAddress):
    try:
        response = IPWhois(IPAddress).lookup_whois()
    except:
        logging.error("WHOIs lookup failed for {}".format(IPAddress))
        return None
    else:
        # Response returns a dictionary with fields: nir, asn_registry, asn, asn_cir, asn_country_code, asn_date, and query
        # and raw, referral, raw_referral
        # There is a subdictionary at ['nets'], that has fields cidr, name, handle, range, description, country, state, city, address
        # postal_code, emails, created, updated
        # Values of interest are name, address, city, state, address, emails, and description
        #print((response['nets'][0].get('name', "None")))    # Gets organization name
        #print(response['asn_country_code'])                 # Country name
        return response


def getHostName(IPAddress):
    try:
        name = socket.gethostbyaddr(IPAddress)[0] # function returns a triple, gets the name from first element
    except:
        name = "DNS Resolution Failure"
    return name

# Parses the specified XML file generated by Masscan and stores the results in the cloud DB
def MassXMLParse(f):
    logging.basicConfig(filename="../Test_Documents/whoistest.log")#export_files.LOGS_DIR + '/xerxes-controller.log', format='[%(levelname)s] %(asctime)s \
                                                  # %(filename)s:%(funcName)s %(lineno)d %(message)s')
    db = Xerxes_SQL.connect_database()     # connect to the DB via credentials
    xmldoc = minidom.parse(f)   # Parse the xml file
    hosts = xmldoc.getElementsByTagName('host') # Gets list of hosts scanned

    for host in hosts:
        # Grab the int version and convert it to human readable
        timeStr = datetime.datetime.fromtimestamp(int(host.attributes['endtime'].value)).strftime('%Y-%m-%d %H:%M:%S')
        # Grabbing rest of hot information from Masscan
        portsList = host.getElementsByTagName('port')
        address = host.getElementsByTagName('address')[0].attributes['addr'].value
        WHOIs_Response = get_WHOIS(address)
        #region = Xerxes_SQL.get_IP_region(db, address) // Deprecated as WHOIS lookup returns the same info and more
        region = WHOIs_Response['asn_country_code']
        returnedName = getHostName(address)
        addressType = host.getElementsByTagName('address')[0].attributes['addrtype'].value

        for port in portsList:
            if port.attributes['portid'].value != 0:    # Disregard host check scan
                serviceList = port.getElementsByTagName('service')
                if len(serviceList) == 0:   # For blank services
                    Xerxes_SQL.insert_into_site_open_services(db, address, port.attributes['portid'].value, "None", "None")
                else:
                    for service in serviceList:
                        Xerxes_SQL.insert_into_site_open_services(db, address, port.attributes['portid'].value, service.attributes['name'].value, service.attributes['banner'].value)

        # Add with just initial info
        Xerxes_SQL.insert_into_whois(db, address, WHOIs_Response)
        Xerxes_SQL.insert_site_entry(db, address, returnedName, addressType, region, timeStr)
    db.close()

# if __name__ == "__main__":    # For testing
# #     #MassXMLParse("..//Test_Documents/xerxes-masscan-out-2.xml")
#     WHOIs_Response = get_WHOIS("172.217.11.238")
#     Xerxes_SQL.insert_into_whois(Xerxes_SQL.connect_database(), "172.217.11.238", WHOIs_Response)

