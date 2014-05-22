#!/usr/bin/sh
DEST=/mylogin
BINDEST=/usr/local/bin
sudo rsync -a mylogin.py passdb.py userdb.py ssh_util.py $DEST/
sudo rsync -a mylogin $BINDEST/
sudo chown root:root $BINDEST/mylogin
sudo chmod 4755 $BINDEST/mylogin
if [ ! -e /etc/spdb ]
then
    sudo mkdir /etc/spdb
fi
sudo rsync -a mylogin.cfg /etc/spdb/
