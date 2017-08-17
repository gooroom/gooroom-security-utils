#!/bin/bash

db_file="db.auth"
dbsig_file="db.sig"

dd bs=1 skip=1425 if=$db_file of=tmp_dbdata

gpg --output $dbsig_file --detach-sign tmp_dbdata 

rm tmp_dbdata
