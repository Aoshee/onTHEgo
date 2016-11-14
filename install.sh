#!/bin/bash
file="key.txt"
# yes I know, easy shell script, but it gets the job done without python and external-
# python modules.
#
# ask for shodan API key
echo "Shodan key: "
read key
echo $key > $file
