#!/bin/bash

for stream in `/home/shawn/Desktop/wireshark-2.2.4/tshark -r /home/shawn/Workspace/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap -T fields -e tcp.stream -2 -R "not (tcp.flags.reset == 1 && tcp.flags.ack == 1)" | sort -n | uniq`
do
    echo $stream
    /home/shawn/Desktop/wireshark-2.2.4/tshark -r /home/shawn/Workspace/Xerxes/Test_Documents/xerxes-masscan-pcap-out-3.pcap -2 -T pdml -R "tcp.stream==$stream" > stream-$stream.xml
done