#!/usr/bin/env bash 


# Load the CVE data into the database

cd /tmp 

git clone https://github.com/securezeron/cve-list.git 

# copy cve data over 

cd -
mkdir -p cve
cp /tmp/cve-list/CVE-2023* ./cve/
