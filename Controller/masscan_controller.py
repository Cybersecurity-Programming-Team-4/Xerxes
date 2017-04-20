import ipaddress
import os
import logging
import subprocess

class MasscanControl:
    IP_INCREMENT = 10000000
    TIME_INCREMENT = 15
    IPV4_INT_START = 1
    IPV4_INT_STOP = 4294967295
    BASE_DIR = '/home/shawnxxxxxxx'
    MASSCAN_BIN = BASE_DIR + '/Xerxes/Scanners/src/masscan/bin/masscan'
    MASSCAN_CMD = '-c ./xerxes-masscan.conf -p {} -oX {} --pcap {} {}-{}'
    XML_OUT = '/var/log/xerxes-masscan-out-{}.xml'
    PCAP_OUT = '/var/log/xerxes-masscan-pcap-out-{}.pcap'

    DEBUG_BASE_DIR = '/home/shawn/Workspace'
    DEBUG_MASSCAN_BIN = DEBUG_BASE_DIR + '/Xerxes/Scanners/src/masscan/bin/masscan'
    DEBUG_MASSCAN_CMD = '-c /home/shawn/Workspace/Xerxes/Controller/xerxes-masscan.conf -p {} -oX {} --pcap {} {}'
    DEBUG_XML_OUT = '/home/shawn/Workspace/Xerxes/xerxes-masscan-out-{}.xml'
    DEBUG_PCAP_OUT = '/home/shawn/Workspace/Xerxes/xerxes-masscan-pcap-out-{}.pcap'

    PORTS = (       20,  # FTP
                    21,  # FTP
                    22,  # SSH/SCP
                    23,  # Telnet
                    25,  # SMTP
                    43,  # WHOIS
                    49,  # TACACS
                    53,  # DNS
                    67,  # DHCP/BOOTP (UDP)
                    68,  # DHCP/BOOTP (UDP)
                    69,  # TFTP (UDP)
                    70,  # Gopher
                    79,  # Finger
                    80,  # HTTP
                    81,  # IP CAMERAS
                    88,  # Kerberos
                    102,  # Microsoft Exchange
                    110,  # POP3
                    111,  # RPC
                    119,  # NNTP (Usenet)
                    123,  # NTP (UDP)
                    135,  # Windows RPC
                    137,  # NetBIOS
                    138,  # NetBIOS
                    139,  # SMB
                    143,  # IMAP4
                    161,  # SNMP (UDP)
                    179,  # BGP
                    201,  # AppleTalk
                    389,  # LDAP
                    443,  # HTTPS
                    445,  # SMB / Microsoft DS
                    500,  # ISAKMP (UDP)
                    513,  # rlogin
                    514,  # Syslog
                    520,  # RIP
                    546,  # DHCPv6
                    547,  # DHCPv6
                    587,  # SMTP
                    902,  # VMWare
                    1080,  # SOCKS / MyDoom (Malicious)
                    1194,  # VPN
                    1337,  # Leet (Malicious)
                    1433,  # MS-SQL
                    1434,  # MS-SQL
                    1521,  # OracleDB
                    1629,  # DameWare
                    2049,  # NFS
                    2745,  # Bagle.H (Malicious)
                    3127,  # MyDoom (Malicious)
                    3128,  # Squid Proxy
                    3306,  # MySQL
                    3389,  # RDP
                    5060,  # SIP
                    5222,  # XMPP - Jabber
                    5432,  # Postgres
                    5666,  # Nagios
                    5900,  # VNC
                    6000,  # X11
                    6129,  # DameWare
                    6667,  # IRC
                    9001,  # TOR/HSQL
                    9090,  # Openfire
                    9091,  # Openfire
                    9100,  # HP Jet Direct
                    27374,  # Sub7 (Malicious)
                    31337,   # Back Orifice (Malicious)
            )

    def __init__(self):
        self.startIP = ipaddress.IPv4Address(MasscanControl.IPV4_INT_START)
        self.endIP = ipaddress.IPv4Address(MasscanControl.IPV4_INT_STOP)
        self.count = 2
        self.ports = str(MasscanControl.PORTS).strip('(').strip(')')

    def scheduleNextScan(self):
        sp = subprocess.run(['at', 'now + {} minutes python3 {}/Controller/main.py'.format(
            MasscanControl.TIME_INCREMENT, os.getcwd())])
        if sp.returncode == 0:
            logging.debug('Scheduled Next Scan: {}\n'.format(sp.args))
        else:
            logging.error('Scan Failed to Schedule! Args: {} Return Code: {}\n'.format(sp.args, sp.returncode))
    def prepNextScan(self):
        nsip = int(self.startIP) + MasscanControl.IP_INCREMENT + 1
        neip = int(self.endIP) + MasscanControl.IP_INCREMENT + 1
        self.count += 1
        if nsip >= MasscanControl.IPV4_INT_STOP:
            logging.info('Masscan Complete!\n')
        elif neip > MasscanControl.IPV4_INT_STOP and nsip < MasscanControl.IPV4_INT_STOP:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(MasscanControl.IPV4_INT_STOP)
        elif neip <= MasscanControl.IPV4_INT_STOP and nsip < neip:
            self.startIP = ipaddress.IPv4Address(nsip)
            self.endIP = ipaddress.IPv4Address(neip)
            self.scheduleNextScan()
        else:
            logging.error('Unhandled case while prepping for next scan! Start IP: {} End IP: {}\n'.format(nsip, neip))
    def oneScan(self, subnet):
        logging.debug('Masscan running. Subnet: {}\n'.format(subnet))

        masscan_done = subprocess.run(['/usr/bin/pkexec', MasscanControl.DEBUG_MASSCAN_BIN, '-c', '/home/shawn/Workspace/Xerxes/Controller/'
            'xerxes-masscan.conf', '-vv', '-p', self.ports, '-oX', MasscanControl.DEBUG_XML_OUT.format(self.count), '--pcap',
            MasscanControl.DEBUG_PCAP_OUT.format(self.count), subnet])

        if masscan_done.returncode == 0:
            logging.debug('Masscan finished with return code 0. Args: {}\n'.format(masscan_done.args))
        else:
            logging.error('Masscan finished with return code {}.\n'.format(masscan_done.returncode))

    def startMasscan(self):
        logging.info('Masscan running. Range: {} - {}\n'.format(str(self.startIP), str(self.endIP)))
        masscan_done = subprocess.run([MasscanControl.MASSCAN_BIN, MasscanControl.MASSCAN_CMD.format(self.ports, MasscanControl.XML_OUT.format(self.count),
                                                            MasscanControl.PCAP_OUT.format(self.count), self.startIP, self.endIP)])
        if masscan_done.returncode == 0:
            logging.info('Masscan finished with return code 0.\n')
            self.prepNextScan()

        else:
            logging.error('Masscan finished with return code {}.\n'.format(masscan_done.returncode))
