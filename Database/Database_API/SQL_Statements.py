#!/usr/bin/python3
import pymysql
import time
import socket

def getHostName(IPAddress):
    try:
        name = socket.gethostbyaddr(IPAddress)[0] # function returns a triple, gets the name from first element
    except:
        name = "DNS Failed to Resolve"
    return  name
# Most generic version
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
       # Execute the SQL command
        cursor.execute(selectStatement)
       # Commit your changes in the database
        data = cursor.fetchall()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("select failed on site info")

    for row in data:
        print(row)

# Basic insert, expects column values to be strings.
def insertSiteEntry(db, ipAddress, hostName, ipVersion, region, openPorts, responses, contents, cms, score, scanDate):
    # Connection to AWS MySQL DB: Endpoint, Username, Password, Database_name
    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_INFO(IP_ADDRESS, \
    SITE_NAME, IP_VERSION, REGION, OPEN_PORTS, RESPONSES, \
    CONTENTS, CMS_TYPE, VULNERABILITY_SCORE, CHECKED_DATE) \
    VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
    (ipAddress, hostName, ipVersion, region, openPorts, responses, contents, cms, score, scanDate)

    print("trying to insert site info")
    try:
       # Execute the SQL command
       cursor.execute(insertStatement)
       # Commit your changes in the database
       db.commit()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("insert failed")
    #db.close()

def retrieveSiteEntry(db, tableField, filterField, filterValue):
    cursor = db.cursor()
    data = {}
    selectStatement = ""
    if filterValue == "None":
        selectStatement = "SELECT %s FROM SITE_INFO" % (tableField)
    else:
        selectStatement = "SELECT %s FROM SITE_INFO WHERE %s = %s" % (tableField, filterField, filterValue)
    print("trying to select site info")
    print ("select statement = " + selectStatement)
    try:
       # Execute the SQL command
        cursor.execute(selectStatement)
       # Commit your changes in the database
        data = cursor.fetchall()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("select failed on site info")

    for row in data:
        print(row)


def insertOpenPort(db, siteIP, portNumber):

    cursor = db.cursor()
    insertStatement = "INSERT INTO SITE_OPEN_PORTS(IP_ADDRESS, PORT_NUMBER) \
    VALUES ('%s', '%s')" % \
    (siteIP, int(portNumber))
    print("trying to insert open port")
    try:
       # Execute the SQL command
       cursor.execute(insertStatement)
       # Commit your changes in the database
       db.commit()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("insert failed on open port")
    #db.close()

def retrieveOpenPortsOnIP(db, siteIP):
    cursor = db.cursor()
    data = {}
    selectStatement = "SELECT * FROM SITE_OPEN_PORTS WHERE SITE_IP = %s" % (siteIP)
    print("trying to select open port")
    try:
       # Execute the SQL command
       cursor.execute("SELECT * FROM SITE_OPEN_PORTS WHERE SITE_IP = %s", siteIP)
       # Commit your changes in the database
       data = cursor.fetchall()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("select failed on open port")
    for row in data:
        print(row)

def retrievePlugins(db, pluginName, CMSName):
    cursor = db.cursor()
    data = {}
    selectStatement = "SELECT * FROM Vulnerable_Plugins WHERE PLUGIN_NAME = %s and CMS = %s" % (pluginName, CMSName)
    print("trying to select open port")
    try:
       # Execute the SQL command
       cursor.execute(selectStatement)
       # Commit your changes in the database
       data = cursor.fetchall()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("select failed on open port")

    if not data:
        print("Plugin not found")
    else:
        for row in data:
            print(row)


def insertIntoScannedSites(db, scanID, siteIP):
    cursor = db.cursor()
    insertStatement = "INSERT INTO SCANNED_SITES (SCAN_IP, SITE_IP) \
    VALUES ('%s', '%s')" % \
    (int(scanID), siteIP)
    print("trying to insert open port")
    try:
       # Execute the SQL command
       cursor.execute(insertStatement)
       # Commit your changes in the database
       db.commit()
    except:
       # Rollback in case there is any error
        db.rollback()
        print("insert failed on open port")

def insertIntoConlusions(db, scanID, vulnerabilityLevel, Result):

    cursor = db.cursor()
    insertStatement = "INSERT INTO CONCLUSIONS (SCAN_ID, VULNERABILITY_LEVEL, RESULT) \
    VALUES ('%s', '%s', '%s')" % \
    (int(scanID), int(vulnerabilityLevel), Result)
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
    insertStatement = "INSERT INTO SCAN_HISTORY (SCAN_ID, SCAN_DATETIME, PARAMTERS, CONCLUSION_ID, SITES_VISITED) \
    VALUES ('%s', '%s', '%s', '%s', '%s')" % \
    (int(scanID), dateTime, scanParameters, conclusionID, sitesVisited)
    try:
       # Execute the SQL command
       cursor.execute(insertStatement)
       # Commit your changes in the database
       db.commit()
    except:
       # Rollback in case there is any error
        db.rollback()

# if __name__ == "__main__":
#     # Connection to AWS MySQL DB: Endpoint, Username, Password, Database_name
#     cursor = db.cursor()
#
#     now = time.strftime('%Y-%m-%d %H:%M:%S')    # To mark time when scan starts, can move below for when scan is finished instead
#     nameStr = 'Gaasdfggl3e4.com'
#     regionStr = 'NZ'
#     IPStr = '123.4.239.101'
#     ipVersion = '4'
#     servicesStr = '53'
#     portResponseStr = 'HTML'
#     contentsStr = 'None\nnone\nnone\none' # will be HTML contents
#
#     #insertSiteEntry(IPStr, nameStr, ipVersion, regionStr, portResponseStr, contentsStr, now)
#     #insertOpenPort(IPStr, 5)
#     retrieveOpenPortsOnIP(IPStr)
#     retrieveSiteEntry("*", "SITE_NAME", "\"Gaggle.com\"")
#     retrieveTableEntry("SITE_INFO", "*", "None", "None")
#     retrievePlugins("\"Adrotate\"", "\"WordPress\"")
# #print("dB version: %s" % data)
