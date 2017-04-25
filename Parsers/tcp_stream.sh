#!/bin/bash

for stream in `$1 -r $2 -T fields -e tcp.stream -2 -R "not (tcp.flags.reset == 1 && tcp.flags.ack == 1)" | sort -n | uniq`
do
    echo $stream
done