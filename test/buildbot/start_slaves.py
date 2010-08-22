#!env python
import sys, os

if len(sys.argv) != 2:
    print "Usage: %s <ssh-private-key>" % sys.argv[0]
    exit(1)
private_key = sys.argv[1]

execfile('master.cfg')
for s in slavenames:
    host = s + '.buildbot'
    env = "BUILDSLAVE=buildslave" if 'win' in s else ""
    if os.system("%s sh create_slave.sh '%s' %s" % \
                     (env, private_key, host)):
        print "ERROR"
