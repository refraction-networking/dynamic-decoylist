#!/bin/bash
rm -f ../list/*.blob
for file in ../list/*.txt; do
  python3  main.py -k prod.apr-11-2017.pubkey -d ${file} -a asn.csv -g 2
done