#!/bin/sh

PRIVATE_KEY=$1
HOST=$2
NAME=${HOST%.buildbot}
SECRET=secret
MASTER=hs02.scs.stanford.edu:9050
BUILDDIR=/tmp/tcbuild

SSH="ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -i $PRIVATE_KEY root@$HOST"

echo creating buildbot $NAME on $HOST
$SSH buildbot create-slave $BUILDDIR $MASTER $NAME $SECRET && \
$SSH eval "uname -a > $BUILDDIR/info/host" && \
(echo `git config --get user.name` "<"`git config --get user.email`">" | $SSH eval "cat > $BUILDDIR/info/admin") && \
$SSH eval "cd $BUILDDIR && buildbot restart" && \
echo buildbot $NAME started on $HOST