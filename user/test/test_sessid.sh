#!/bin/sh
PIDFILE=/var/run/tcpcrypt.pid

`dirname $0`/../launch_tcpcryptd.sh &
sleep 2
RES=$(curl http://tcpcrypt.org/sessid.php 2>/dev/null | grep -v NONE)
RET=$?
kill `cat $PIDFILE 2>/dev/null` > /dev/null 2>&1
rm -f $PIDFILE
echo "$RES"
exit $RET
