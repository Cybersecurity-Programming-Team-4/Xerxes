#!/usr/bin/python3
import ipaddress
import socket
import struct
import mmap
import sys
import os


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


if __name__ == '__main__':
    # file = open('GeoLite2-City-Blocks-IPv4.csv', 'r+')  # Open the file in read + write mode
    file = open('GeoLite2-City-Blocks-IPv4.csv', 'r+')  # Open the file in read + write mode
    outFile = open('NewGeoCityBlocks.csv', 'w')
    # with open('GeoIP_Sample.txt') as f:
    #     data = mmap.mmap(file.fileno(), 0)  # Make a memory mapped file object of the entire file
    #     for line in data:#iter(data.readline, "\n"):
    #         print(line)
    for line in file:
        # print(str(line))
        line = line.strip('\n')
        splitLine = line.split(',')
        # print(splitLine)
        # print(splitLine[0])
        subnet = ipaddress.IPv4Network(splitLine[0])
        rangeStart = ip2int(str(subnet[0]))
        rangeEnd = ip2int(str(subnet[-1]))
        newLine = splitLine[0] + "," + str(rangeStart) + "," + str(rangeEnd) + "," + splitLine[1] + "," + splitLine[2] + "\n"
        outFile.write(newLine)
        #print("int form: start = " + str(ip2int(str(rangeStart))) + " end = " + str(ip2int(str((rangeEnd)))))
        #outFile.write()
    outFile.close()
    file.close()
    # subnet = ipaddress.IPv4Network('255.255.255.0/24')
    # rangeStart = ip2int(str(subnet[0]))
    # rangeEnd = ip2int(str(subnet[-1]))
    # print(str(rangeEnd))

