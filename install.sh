#!/bin/bash
file="key.txt"
# ask for shodan API key
echo "Shodan key: "
read key
echo $key > $file
