#!/usr/bin/python3
import pymysql
import socket
import struct

# def write_log(log_name, log_info):
#     with open
# To map well-known port to the expected service when listing results

def map_port_service(port_number):
    # Dictionary of Port Numbers and their Services
    portDict = {1 : 'TCPMUX',
                5 : 'RJE',
                7 : 'ECHO',
                18 : 'MSP',
                20 : 'FTP-Data',
                21 : 'FTP-Control',
                22 : 'SSH',
                23 : 'Telnet',
                25 : 'SMTP',
                29 : 'MSG ICP',
                37 : 'Time',
                42 : 'Nameserv',
                43 : 'WhoIs',
                49 : 'Login',
                53 : 'DNS',
                69 : 'TFTP',
                80 : 'HTTP',
                109 : 'POP2',
                110 : 'POP3',
                115 : 'SFTP',
                118 : 'SQL Services',
                119 : 'NNTP',
                137 : 'NetBIOS Name',
                139 : 'NetBIOS Datagram',
                143 : 'IMAP',
                150 : 'NetBIOS Session',
                156 : 'SQL Server',
                161 : 'SNMP',
                179 : 'BGP',
                190 : 'GACP',
                194 : 'IRC',
                197 : 'DLS',
                389 : 'LDAP',
                396 : 'Novell Netware',
                443 : 'HTTPS',
                444 : 'SNPP',
                445 : 'Microsoft-DS',
                458 : 'Apple QuickTime',
                546 : 'DHCP Client',
                547 : 'DHCP Server'}
    return portDict.get(port_number, "")

# Local connection to DB, grabbing credentials from local file
# TODO have Google app connect without needing to call connect
def connect_database():
    with open("DatabaseInfo.txt") as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    content = [x.strip() for x in content]
    return pymysql.connect(content[0], content[1], content[2], content[3], local_infile = 1)

def get_IP_region(db, IP_address):
    cursor = db.cursor()
    int_form = struct.unpack("!I", socket.inet_aton(IP_address))[0]
    selectStatement = "SELECT COUNTRY FROM GEOIP_LOCATION_INFO AS B \
    JOIN GEOIP_IP_BLOCKS AS A \
    ON A.GEONAME_ID = B.GEONAME \
    WHERE %s >= A.NETWORK_START AND %s <= A.NETWORK_END" % \
                      (int_form, int_form)

    try:
        cursor.execute(selectStatement)
        db.commit()
    except:
        db.rollback()
        print("select country failed")
        return "NULL"
    data = cursor.fetchall()

    return data[0][0]   # Return the country name serving as the region

def get_GEOIP_Info(db, IP_address, field):
    cursor = db.cursor()
    int_form = struct.unpack("!I", socket.inet_aton(IP_address))[0]
    selectStatement = "SELECT * FROM GEOIP_LOCATION_INFO AS B \
    JOIN GEOIP_IP_BLOCKS AS A \
    ON A.GEONAME_ID = B.GEONAME \
    WHERE %s >= A.NETWORK_START AND %s <= A.NETWORK_END" % \
                      (int_form, int_form)

    try:
        cursor.execute(selectStatement)
        db.commit()
    except:
        db.rollback()
        return "NULL"
    data = cursor.fetchall()

    return data   # Return the country information as a dictionary

def retrieveTableEntry(db, tableName, tableField, filterField, filterValue):
    cursor = db.cursor()
    data = {}
    if filterValue == "None" or filterField == "None":
        selectStatement = "SELECT %s FROM %s" % (tableField, tableName)
    else:
        selectStatement = "SELECT %s FROM %s WHERE %s = %s" % (tableField, tableName, filterField, filterValue)
    print("trying to select site info")
    print ("select statement = " + selectStatement)
    try:
        cursor.execute(selectStatement)
        data = cursor.fetchall()
    except:
        db.rollback()
        print("select failed on site info")

    for row in data:
        print(row)


# Basic insert, expects column values to be strings.
def insert_site_entry(db, ipAddress, hostName, ipVersion, region, cms, score, scanDate):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_INFO(IP_ADDRESS, \
    SITE_NAME, IP_VERSION, COUNTRY, CMS_TYPE, VULNERABILITY_SCORE, CHECKED_DATE) \
    VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS, SITE_NAME = SITE_NAME, IP_VERISON = IP_VERSION, COUNTRY = COUNTRY \
    CMS_TYPE = CMS_TYPE, VULNERABILITY_SCORE = VULNERABILITY_SCORE, CHECKED_DATE = CHECKED_DATE \ " % \
    (ipAddress, hostName, ipVersion, region, cms, score, scanDate)

    try:
        cursor.execute(insertStatement)
        db.commit()
    except Exception as e:
        db.rollback()
        return "[error] with insert entry", e

def updateSiteEntry(db, IP_address, field, new_value):
    cursor=db.cursor()
    update_statement = "UPDATE SITE_INFO SET %s = %s WHERE IP_ADDRESS = %s" % (IP_address, field, new_value)
    try:
        cursor.execute(update_statement)
        db.commit()
    except:
        db.rollback()
        print("Update failed")

def retrieveSiteEntry(db, tableField, filterField, filterValue):
    cursor = db.cursor()
    if filterValue == "None":
        selectStatement = "SELECT %s FROM SITE_INFO" % (tableField)
    else:
        selectStatement = "SELECT %s FROM SITE_INFO WHERE %s = %s" % (tableField, filterField, filterValue)
    try:
        cursor.execute(selectStatement)
        data = cursor.fetchall()
    except:
        db.rollback()
        return  "Site not found"
    return data

def insert_into_CVE_vulnerabilities(db, CVE_id, status, description):

    cursor = db.cursor()
    insertStatement = "INSERT INTO CVE_VULNERABILITIES(CVE_ID, STATUS, DESCRIPTION) \
    VALUES ('%s', '%s', '%s') \
    ON DUPLICATE KEY UPDATE  \
    CVE_ID = VALUES(CVE_ID), STATUS = VALUES(STATUS), DESCRIPTION = VALUES(DESCRIPTION)" % \
    (CVE_id, status, description)
    # Execute the SQL command

    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        # Commit your changes in the database
        db.commit()
    except:
        # Rollback in case there is any error
        db.rollback()
        print("Insert Failed on CVE Update")
        #db.close()

def CMS_extension_lookup(db, name, cms_type):
    cursor = db.cursor()
    select_statement = "SELECT EXISTS(SELECT 1  \
    FROM CMS_VULNERABILITIES \
    WHERE EXTENSION_NAME = '%s' AND CMS = '%s' \
    LIMIT 1)" % (name, cms_type)
    cursor.execute(select_statement)
    data = cursor.fetchone()
    # try:
    #     # Execute the SQL command
    #     cursor.execute(select_statement)
    #     data = cursor.fetchall()
    #     # Commit your changes in the database
    #     db.commit()
    # except:
    #     # Rollback in case there is any error
    #     db.rollback()
    #     return False
    print("data = ")
    print(data[0])
    if data[0] == 1:
        print("returning true")
        return True
    else:
        return False
        #db.close()
def insert_into_site_open_services(db, siteIP, portNumber, service_name, banner):

    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_OPEN_SERVICES(IP_ADDRESS, PORT_NUMBER, SERVICE_NAME, BANNER) \
    VALUES ('%s', '%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS, PORT_NUMBER = PORT_NUMBER, SERVICE_NAME = SERVICE_NAME, BANNER = BANNER " % \
    (siteIP, int(portNumber), service_name, banner)

    cursor.execute(insertStatement)
    # Commit your changes in the database
    db.commit()
    # try:
    #     # Execute the SQL command
    #     cursor.execute(insertStatement)
    #     # Commit your changes in the database
    #     db.commit()
    # except:
    #     # Rollback in case there is any error
    #     db.rollback()
    #     print("insert failed on open port")
    #     #db.close()

def retrieveOpenPortsOnIP(db, siteIP):
    cursor = db.cursor()
    data = {}
    try:
        cursor.execute("SELECT * FROM SITE_OPEN_PORTS WHERE SITE_IP = %s", siteIP)
        data = cursor.fetchall()
    except:
        db.rollback()
    for row in data:
        print(row)

def retrievePlugins(db, plugin_name, CMS_name):
    cursor = db.cursor()
    data = {}
    selectStatement = "SELECT * FROM Vulnerable_Plugins WHERE CMS = %s and PLUGIN_NAME = %s" % (CMS_name, plugin_name)
    try:
        cursor.execute(selectStatement)
        data = cursor.fetchall()
    except:
        db.rollback()
        return "Database Error"

    if not data:
        return "Plugin not found"
    else:
        return data

def insert_into_vulnerable_plugins(db, name, cms_type, min_ver, max_ver, description):
    cursor = db.cursor()
    # Where type is either a CVE Reference, CMS-related
    # Description is the CVE ID, or if CMS-related, something such as accessible Admin Login Page
    insertStatement = "INSERT INTO VULNERABLE_PLUGINS (PLUGIN_NAME, CMS, MIN_VERSION, MAX_VERSION, DESCRIPTION) \
    VALUES ('%s', '%s', '%s', '%s', '%s')  \
    ON DUPLICATE KEY \
        UPDATE CMS = CMS, MIN_VERSION = MIN_VERSION, MAX_VERSION = MAX_VERSION, DESCRIPTION = DESCRIPTION" % \
                      (name, cms_type, min_ver, max_ver, description)
    try:
        cursor.execute(insertStatement)
        db.commit()
    except:
        db.rollback()

def insert_into_site_vulnerabilities(db, IP_address, type, description):
    cursor = db.cursor()
    # Where type is either a CVE Reference, CMS-related
    # Description is the CVE ID, or if CMS-related, something such as accessible Admin Login Page
    insertStatement = "INSERT INTO SITE_VULNERABILITIES (IP_ADDRESS, TYPE, DESCRIPTION) \
    VALUES ('%s', '%s', '%s') \
    ON DUPLICATE KEY \
        UPDATE TYPE = TYPE, DESCRIPTION = DESCRIPTION"% \
                      (IP_address, type, description)

    try:
        cursor.execute(insertStatement)
        db.commit()
    except:
        db.rollback()

def insertIntoConlusions(db, scanID, vulnerabilityLevel, Result):

    cursor = db.cursor()
    insertStatement = "INSERT INTO CONCLUSIONS (ID, DESCRIPTION) \
    VALUES ('%s', '%s')" % \
                      (int(scanID), Result)
    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        # Commit your changes in the database
        db.commit()
    except:
        # Rollback in case there is any error
        db.rollback()
        print("insert failed on open port")
    db.close()

def insertIntoScanHistory(db, scanID, dateTime, scanParameters, conclusionID, sitesVisited):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SCAN_HISTORY (SCAN_ID, SCAN_DATETIME, PARAMETERS, CONCLUSION_ID, SITES_SCANNED) \
    VALUES ('%s', '%s', '%s', '%s', '%s')" % \
                      (int(scanID), dateTime, scanParameters, conclusionID, sitesVisited)
    try:
        cursor.execute(insertStatement)
        db.commit()
    except:
        db.rollback()



