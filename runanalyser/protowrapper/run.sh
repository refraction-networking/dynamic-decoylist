#!/bin/bash
rm -f ../list/*.blob
currentDate=`date +"%Y%m%d"`
for file in ../list/*.txt; do
  python3  main.py -k prod.apr-11-2017.pubkey -d ${file} -a asn.csv -g $currentDate
done

git clone git@github.com:refraction-networking/decoy-lists.git
cp ../list/IR_Active.txt.blob decoy-lists/current_decoys_iran.blob
cd decoy-lists
git add .
git commit -m "daily iran update $currentDate"
git push

cd ..
rm -rf decoy-lists