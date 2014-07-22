#!/bin/sh

DIR=$1

pkgbuild --root $DIR --identifier org.tcpcrypt.TcpcryptLauncher \
	--version 0.2 --install-location /Applications  tcpcrypt.pkg 
