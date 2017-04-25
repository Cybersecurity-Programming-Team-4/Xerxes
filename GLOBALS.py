import os

IP_INCREMENT = 10000000
TIME_INCREMENT = 15
IPV4_INT_START = 1
IPV4_INT_STOP = 4294967295
BASE_DIR = os.getcwd()
MASSCAN_BIN = BASE_DIR + '/Scanners/src/masscan/bin/masscan'
MASSCAN_CMD = '-c ./xerxes-masscan.conf -p {} -oX {} --pcap {} {}-{}'
XML_OUT = BASE_DIR + '/OutFiles/xerxes-masscan-out-{}.xml'
PCAP_OUT = BASE_DIR + '/OutFiles/xerxes-masscan-pcap-out-{}.pcap'

OUT_DIR = BASE_DIR + '/OutFiles/'

TSHARK_BIN = ''

DEBUG_BASE_DIR = os.getcwd()
DEBUG_MASSCAN_BIN = DEBUG_BASE_DIR + '/Scanners/src/masscan/bin/masscan'
DEBUG_MASSCAN_CMD = '-c ' + DEBUG_BASE_DIR + '/Controller/xerxes-masscan.conf -p {} -oX {} --pcap {} {}'
MASSCAN_CONF = DEBUG_BASE_DIR + '/Controller/xerxes-masscan.conf'
DEBUG_XML_OUT = DEBUG_BASE_DIR + '/OutFiles/xerxes-masscan-out-{}.xml'
DEBUG_PCAP_OUT = DEBUG_BASE_DIR + '/OutFiles/xerxes-masscan-pcap-out-{}.pcap'

PORTS = {           20 : 'FTP',
                    21 : 'FTP',
                    22 : 'SSH',
                    23 : 'Telnet',
                    25 : 'SMTP',
                    43 : 'WHOIS',
                    49 : 'TACACS',
                    53 : 'DNS',
                    #67 : 'DHCP/BOOTP (UDP)',
                    #68 : 'DHCP/BOOTP (UDP)',
                    69 : 'TFTP',
                    70 : 'Gopher',
                    79 : 'Finger',
                    80 : 'HTTP',
                    81 : 'IP CAMERAS',
                    88 : 'Kerberos',
                    101 : 'Wonderware',
                    102 : 'Microsoft Exchange',
                    110 : 'POP3',
                    111 : 'RPC',
                    119 : 'NNTP (Usenet)',
                    123 : 'NTP (UDP)',
                    135 : 'Windows RPC',
                    137 : 'NetBIOS',
                    138 : 'NetBIOS',
                    139 : 'SMB',
                    143 : 'IMAP',
                    #161 : 'SNMP (UDP)',
                    #179 : 'BGP',
                    201 : 'AppleTalk',
                    389 : 'LDAP',
                    443 : 'HTTPS',
                    445 : 'SMB / Microsoft DS',
                    500 : 'ISAKMP',
                    513 : 'rlogin',
                    514 : 'Syslog',
                    520 : 'RIP',
                    #546 : 'DHCPv6',
                   # 547 : 'DHCPv6',
                    587 : 'SMTP',
                    902 : 'VMWare',
                    1080 : 'SOCKS',
                    1194 : 'OpenVPN',
                    #1337 : 'Leet (Malicious)',
                    1433 : 'MS-SQL',
                    1434 : 'MS-SQL',
                    1521 : 'OracleDB',
                    1629 : 'DameWare',
                    2049 : 'NFS',
                    #2745 : 'Bagle.H (Malicious)',
                    #3127 :'MyDoom (Malicious)',
                    3128 : 'Squid Proxy',
                    3306 : 'MySQL',
                    3389 : 'RDP',
                    5060 : 'SIP',
                    5222 : 'XMPP',
                    5432 : 'Postgres',
                    5666 : 'Nagios',
                    5900 : 'VNC',
                    5901 : 'VNC',
                    5902 : 'VNC',
                    5903 : 'VNC',
                    5904 : 'VNC',
                    5905 : 'VNC',
                    5906 : 'VNC',
                    5907 : 'VNC',
                    5908 : 'VNC',
                    5909 : 'VNC',
                    5910 : 'VNC',
                    6000 : 'X11',
                    6129 : 'DameWare',
                    6667 : 'IRC',
                    9001 : 'TOR/HSQL',
                    9090 : 'websm',
                    9091 : 'xmltec-xmlmail',
                    9100 : 'PDL Data Streaming'
                    #27374 : 'Sub7 (Malicious)'
                    #31337 : 'Back Orifice (Malicious)'
}

FIELDS = {
    'data' : ['data.data', 'data.text'],
    'eth' : [ 'eth.src', 'eth.src_resolved'],
    'tcp' : ['tcp.srcport'],
    'ip' : ['ip.src'],
    'http' : ['http.accept', 'http.accept_encoding', 'http.accept_language', 'http.authbasic', 'http.authcitrix',
            'http.http.authcitrix.domain', 'http.authcitrix.password', 'http.authcitrix.session', 'http.authcitrix.user',
            'http.authorization', 'http.cache_control', 'http.connection', 'http.content_encoding', 'http.content_type',
            'http.file_data', 'http.host', 'http.location', 'http.proxy_authenticate', 'http.proxy_authorization', 'http.proxy_connect_host',
            'http.proxy_connect_port', 'http.response.code', 'http.response.line', 'http.response.phrase', 'http.server', 'http.ssl_port',
            'http.transfer_encoding', 'http.unknown_header', 'http.www_authenticate', 'http.x_forwarded_for'],
    'http2' : ['http2.altsvc.field_value', 'http2.altsvc.host', 'http2.altsvc.origin', 'http2.altsvc.protocol', 'http2.continuation.header',
            'http2.data.data', 'http2.settings', 'http2.unknown']



}


ERROR = 1
SUCCESS = 0
