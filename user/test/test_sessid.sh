#!/bin/sh

`dirname $0`/../launch_tcpcryptd.sh &
sleep 2
RES=$(curl http://tcpcrypt.org/sessid.php 2>/dev/null | grep -v NONE)
RET=$?
killall tcpcryptd > /dev/null
echo "$RES"
return $RET