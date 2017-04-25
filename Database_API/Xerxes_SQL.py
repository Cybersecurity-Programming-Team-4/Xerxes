#!/usr/bin/python3
import pymysql
import socket
import struct
import logging
import datetime

# Code to interact with Xerxes' CloudSQL Database with python code running SQL statementss

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
# TODO encrypt and decrypt file with DB credentials
def connect_database():
    with open("DatabaseInfo.txt") as f:
        content = f.readlines()
        content = [x.strip() for x in content]

    try:
        return pymysql.connect(content[0], content[1], content[2], content[3], local_infile = 1)
    except:
        logging.error("CRITICAL ERROR: CAN'T CONNECT TO DATABASE {}".format(datetime.datetime.now()))
        exit(-1)


# Basic insert, expects column values to be strings.
def insert_site_entry(db, IP_address, hostName, ipVersion, region, scanDate):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_INFO(IP_ADDRESS, \
    SITE_NAME, IP_VERSION, COUNTRY, CMS_TYPE, VULNERABILITY_SCORE, CHECKED_DATE) \
    VALUES ('%s', '%s', '%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS, SITE_NAME = SITE_NAME, IP_VERSION = IP_VERSION, COUNTRY = COUNTRY, CHECKED_DATE = CHECKED_DATE" % \
    (IP_address, hostName, ipVersion, region, scanDate)

    try:
        cursor.execute(insertStatement)
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error("Failed to insert {} in SITE_INFO Table".format(IP_address))
        return "[error] with insert entry", e

def update_site_entry(db, IP_address, field, new_value):
    cursor=db.cursor()
    update_statement = "UPDATE SITE_INFO SET %s = %s WHERE IP_ADDRESS = %s" % (IP_address, field, new_value)
    try:
        cursor.execute(update_statement)
        db.commit()
    except:
        db.rollback()
        logging.error("Update for {}, field = {} failed".format(IP_address, field))

def retrieve_site_entry(db, table_field, filter_field, filter_value):
    cursor = db.cursor()
    if filter_value == "None":
        selectStatement = "SELECT %s FROM SITE_INFO" % (table_field)
    else:
        selectStatement = "SELECT %s FROM SITE_INFO WHERE %s = %s" % (table_field, filter_field, filter_value)
    try:
        cursor.execute(selectStatement)
        data = cursor.fetchall()
    except:
        db.rollback()
        return  "Site not found"
    return data

def insert_device_entry(db, IP_address, MAC_address, taxonomy, vendor):
    cursor = db.cursor()
    insertStatement = "INSERT INTO DEVICE_INFO \
    (IP_ADDRESS, MAC_ADDRESS, VENDOR) \
    VALUES ('%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS, MAC_ADDRESS = MAC_ADDRESS, VENDOR = VENDOR" % \
    (IP_address, MAC_address, vendor)

    try:
        cursor.execute(insertStatement)
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error("Failed to insert {} in DEVICE_INFO Table".format(IP_address))
        return "[error] with insert entry", e

def insert_into_whois(db, IP_address, response):
    cursor = db.cursor()
    email_str = ""
    if response['nets'][0].get('emails', "None") == None: # WHOIS lookup on that IP didn't provide any emails/contact info
        email_str = "None"
    else:
        for email in response['nets'][0].get('emails', "None"):
            email_str = email_str + email + ", "
        email_str = email_str[:-2]  # Remove the formatting characters at the end

    insertStatement = "INSERT INTO WHOIS_INFO(IP_ADDRESS, ORGANIZATION, COUNTRY, STATE, CITY, ADDRESS, DESCRIPTION, CONTACT) \
    VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS" % \
    (IP_address, response['nets'][0].get('name', "None"), response['nets'][0].get('country', "None"),
        response['nets'][0].get('state', "None"), response['nets'][0].get('city', "None"), response['nets'][0].get('address', "None"),
        response['nets'][0].get('description', "None"), email_str)

    cursor.execute(insertStatement)
    db.commit()
    # try:
    #     # Execute the SQL command
    #     cursor.execute(insertStatement)
    #     db.commit()
    # except:
    #     # Rollback in case there is any error
    #     db.rollback()
    #     logging.error("Insert failed on WHOIS for IP \"{}\"".format(IP_address))

def insert_into_site_open_services(db, IP_address, portNumber, service_name, banner):

    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_OPEN_SERVICES(IP_ADDRESS, PORT_NUMBER, SERVICE_NAME, BANNER) \
    VALUES ('%s', '%s', '%s', '%s') \
    ON DUPLICATE KEY \
    UPDATE IP_ADDRESS = IP_ADDRESS, PORT_NUMBER = PORT_NUMBER, SERVICE_NAME = SERVICE_NAME, BANNER = BANNER " % \
    (IP_address, int(portNumber), service_name, banner)

    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        db.commit()
    except:
        # Rollback in case there is any error
        db.rollback()
        logging.error("Insert failed on OPEN_SERVICE for IP \"{}\"".format(IP_address))

def insert_into_site_vulnerabilities(db, IP_address, type, description):
    cursor = db.cursor()
    # Where type is either a CVE Reference, CMS-related
    # Description is the CVE ID, or if CMS-related, something such as accessible Admin Login Page
    insertStatement = "INSERT INTO SITE_VULNERABILITIES (IP_ADDRESS, TYPE, DESCRIPTION) \
    VALUES ('%s', '%s', '%s') \
    ON DUPLICATE KEY \
        UPDATE TYPE = TYPE, DESCRIPTION = DESCRIPTION" % \
                      (IP_address, type, description)

    try:
        cursor.execute(insertStatement)
        db.commit()
    except:
        db.rollback()
        logging.error("Insert failed for {} site vulnerability: {}".format(IP_address, description))

def retrieve_site_vulnerabilities(db, IP_Address):
    cursor = db.cursor()
    try:
        cursor.execute("SELECT * FROM SITE_VULNERABILITIES WHERE IP_ADDRESS = %s", IP_Address)
    except:
        db.rollback()
        logging.error("Failed to retrieve vulnerabilities for {}".format(IP_Address))
        return None
    else:
        return cursor.fetchall()

def insert_into_scan_history(db, start_time, end_time):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SCAN_HISTORY (SCAN_ID, START_TIME, END_TIME) \
    VALUES ('%s', '%s')" % \
    (start_time, end_time)
    try:
        cursor.execute(insertStatement)
        db.commit()
    except:
        logging.error("Could not record scan history for scan information from {} to {}".format(start_time, end_time))
        db.rollback()

def insert_into_CVE_vulnerabilities(db, CVE_id, status, description):
    cursor = db.cursor()
    insertStatement = "INSERT INTO CVE_VULNERABILITIES(CVE_ID, STATUS, DESCRIPTION) \
    VALUES ('%s', '%s', '%s') \
    ON DUPLICATE KEY UPDATE  \
    CVE_ID = VALUES(CVE_ID), STATUS = VALUES(STATUS), DESCRIPTION = VALUES(DESCRIPTION)" % \
    (CVE_id, status, description)

    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        # Commit your changes in the database
        db.commit()
    except:
        # Rollback in case there is any error
        db.rollback()
        logging.debug("Insert Failed on CVE Update for {}".format(CVE_id))

def insert_scan_requests(db, request_id, requester, target, submission_time):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SCAN_REQUESTS (REQUEST_ID, REQUESTER, TARGET_IP, SUBMISSION_TIME) \
    VALUES ('%s', '%s', '%s', '%s') \
    ON DUPLICATE IGNORE" % \
                      (int(request_id), requester, target, submission_time)

    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        db.commit()
    except:
        db.rollback()
        logging.debug("Failed to record request from {}".format(requester))
        db.close()

def insert_new_user(db, username, password_hash, salt, level, API_key):
    cursor = db.cursor()
    insertStatement = "INSERT INTO USERS (USERNAME, PASSWORD, SALT, LEVEL, API_KEY) \
    VALUES ('%s', '%s', '%s', '%s', '%s')" % \
    (username, password_hash, salt, level, API_key)

    try:
        # Execute the SQL command
        cursor.execute(insertStatement)
        # Commit your changes in the database
        db.commit()
    except:
        # Rollback in case there is any error
        db.rollback()
        logging.debug("Failed to store account for {}".format(username))
        db.close()

def get_IP_region(db, IP_address):
    cursor = db.cursor()
    int_form = struct.unpack("!I", socket.inet_aton(IP_address))[0]
    selectStatement = "SELECT COUNTRY FROM GEOIP_LOCATION_INFO AS B \
    JOIN GEOIP_IP_BLOCKS AS A \
    ON A.GEONAME_ID = B.GEONAME_ID \
    WHERE %s >= A.NETWORK_START AND %s <= A.NETWORK_END" % \
    (int_form, int_form)

    try:
        cursor.execute(selectStatement)
        db.commit()
    except:
        db.rollback()
        return "NULL"
    else:
        data = cursor.fetchall()
        return data[0][0]   # Return the country name serving as the region

def get_GEOIP_info(db, IP_address, field):
    cursor = db.cursor()
    int_form = struct.unpack("!I", socket.inet_aton(IP_address))[0]
    selectStatement = "SELECT * FROM GEOIP_LOCATION_INFO AS B \
    JOIN GEOIP_IP_BLOCKS AS A \
    ON A.GEONAME_ID = B.GEONAME_ID \
    WHERE %s >= A.NETWORK_START AND %s <= A.NETWORK_END" % \
    (int_form, int_form)

    try:
        cursor.execute(selectStatement)
        db.commit()
    except:
        db.rollback()
        logging.debug("Error fetching GEOIP Location Data")
        return "NULL"
    else:
        return cursor.fetchone()

def CMS_extension_lookup(db, name, cms_type):
    cursor = db.cursor()
    select_statement = "SELECT EXISTS(SELECT 1  \
    FROM CMS_VULNERABILITIES \
    WHERE EXTENSION_NAME = '%s' AND CMS = '%s' \
    LIMIT 1)" % (name, cms_type)

    try:
        # Execute the SQL command
        cursor.execute(select_statement)
        data = cursor.fetchall()
        # Commit your changes in the database
        db.commit()
    except:
        # Rollback in case there is any error
        logging.debug("CMS Extension lookup error")
        db.rollback()
        return False

    if data[0] == 1:
        print("returning true")
        return True
    else:
        return False
        #db.close()

def retrieve_table_entry(db, tableName, tableField, filterField, filterValue):
    cursor = db.cursor()
    if filterValue == "None" or filterField == "None":
        selectStatement = "SELECT %s FROM %s" % (tableField, tableName)
    else:
        selectStatement = "SELECT %s FROM %s WHERE %s = %s" % (tableField, tableName, filterField, filterValue)
    try:
        cursor.execute(selectStatement)
        return cursor.fetchall()
    except:
        db.rollback()
        logging.debug("Error fetching {} data".format(tableName))
        return None

# Defunct as update code will just load the data in and themes and plugins have been consolidated into one table
# def insert_into_vulnerable_plugins(db, name, cms_type, min_ver, max_ver, description):
#     cursor = db.cursor()
#     # Where type is either a CVE Reference, CMS-related
#     # Description is the CVE ID, or if CMS-related, something such as accessible Admin Login Page
#     insertStatement = "INSERT INTO VULNERABLE_PLUGINS (PLUGIN_NAME, CMS, MIN_VERSION, MAX_VERSION, DESCRIPTION) \
#     VALUES ('%s', '%s', '%s', '%s', '%s')  \
#     ON DUPLICATE KEY \
#         UPDATE CMS = CMS, MIN_VERSION = MIN_VERSION, MAX_VERSION = MAX_VERSION, DESCRIPTION = DESCRIPTION" % \
#                       (name, cms_type, min_ver, max_ver, description)
#     try:
#         cursor.execute(insertStatement)
#         db.commit()
#     except:
#         db.rollback()





