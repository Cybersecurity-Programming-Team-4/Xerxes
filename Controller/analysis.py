from Database_API import Xerxes_SQL
from Parsers import Masscan_Parser

class WiseShark:
    PCAP_TO_XML = '/home/shawn/Desktop/wireshark-2.2.6/tshark -r xerxes-masscan-pcap-out-3.pcap -T pdml'
    def __init__(self, xml, pcap):
        self.xmlf = xml
        self.pcapf = pcap

    def getVNC(self):
        pass
    def deviceInfo(self):

        pass

