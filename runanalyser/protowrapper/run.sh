#!/bin/bash
rm -f ../list/*.blob
currentDate=`date +"%Y%m%d"`
for file in ../list/*.txt; do
  python3  main.py -k prod.apr-11-2017.pubkey -d ${file} -a asn.csv -g $currentDate
done