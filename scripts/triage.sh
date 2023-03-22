#!/usr/bin/env bash
INFILE=$1
OUTFILE=$2
grep -A1 "    --- FAIL" $INFILE | cut -d':' -f2- | grep 'Fuzz\|panic' > panicsRaw.txt
paste -d ","  - - < panicsRaw.txt > panicsPPStep1.txt
sed 's/(.*s)//g' panicsPPStep1.txt | sed 's/1349: //g' > $OUTFILE
rm -f panicsRaw.txt panicsPPStep1.txt
