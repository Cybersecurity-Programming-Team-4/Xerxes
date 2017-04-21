#!/usr/bin/python3
import ipaddress
import socket
import struct

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


if __name__ == '__main__':
    file = open('GeoLite2-City-Blocks-IPv4.csv', 'r+')  # Open the file in read + write mode
    outFile = open('NewGeoCityBlocks.csv', 'w')

    for line in file:
        line = line.strip('\n')
        splitLine = line.split(',')
        subnet = ipaddress.IPv4Network(splitLine[0])
        rangeStart = ip2int(str(subnet[0]))
        rangeEnd = ip2int(str(subnet[-1]))
        newLine = splitLine[0] + "," + str(rangeStart) + "," + str(rangeEnd) + "," + splitLine[1] + "," + splitLine[2] + "\n"
        outFile.write(newLine)

    outFile.close()
    file.close()
