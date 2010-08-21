#!/bin/sh

PRIVATE_KEY=$1
HOST=$2
NAME=${HOST%.buildbot}
SECRET=secret
MASTER=hs02.scs.stanford.edu:9989
BUILDDIR=/tmp/tcbuild

BUILDSLAVE=${BUILDSLAVE-buildbot} # new buildbot vers use buildslave
SSH="ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -i $PRIVATE_KEY root@$HOST"

echo creating buildbot $NAME on $HOST
$SSH rm -rf $BUILDDIR/buildbot.tac
$SSH mkdir -p $BUILDDIR/build/$NAME
$SSH $BUILDSLAVE create-slave $BUILDDIR $MASTER $NAME $SECRET && \
$SSH eval "uname -a > $BUILDDIR/info/host" && \
(echo `git config --get user.name` "<"`git config --get user.email`">" | $SSH eval "cat > $BUILDDIR/info/admin") && \
$SSH eval "cd $BUILDDIR && $BUILDSLAVE restart $BUILDDIR" && \
echo buildbot $NAME started on $HOST