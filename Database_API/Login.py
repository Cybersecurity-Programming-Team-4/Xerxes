#!/usr/bin/python3

import pymysql
import hashlib
from Xerxes_SQL import *

def checkLogin(db, username, password):
    cursor = db.cursor()
    password_statement = "SELECT PASSWORD, SALT FROM USERS WHERE USERNAME = " + "\'" + username + "\'"
    print ("select statement = " + password_statement)

    try:
        cursor.execute(password_statement)
        data = cursor.fetchone()
        hashed_pass = hashlib.sha256((password + data[1]).encode('utf-8')).hexdigest()
        if hashed_pass == data[0]:
            print("Correct Login")
            return True
        else:
            print("incorrect")
            return False
    except:
        db.rollback()
        print("select failed on password")
        # Security measure, still want password hash check to have similar response time
        hashed_pass = hashlib.sha256(("BogusString" + "bogusSalt").encode('utf-8')).hexdigest()
        return False



if __name__ == "__main__":
    with open("DatabaseInfo.txt") as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    content = [x.strip() for x in content]

    db = pymysql.connect(content[0], content[1], content[2], content[3])
    checkLogin(db, "TEST2", "TEST2")
    db.close()
    #salt = "TEST2"
    #passW = "TEST2"
    #hashed_password = hashlib.sha256((passW + salt).encode('utf-8')).hexdigest()
    #print(hashed_password)
