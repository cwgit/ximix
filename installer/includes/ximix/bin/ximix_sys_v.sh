#!/bin/bash

#
# chkconfig: 35 90 12
# description: Ximix Node
#

# Define the node.
#
NODE=node1
#

#
# The user to run ximix under.

if [[ "x$XIMIX_USER" = "x" ]]; then
	XIMIX_USER=ximix
fi


#
# Where to direct stdout and stderr
#
if [[ "x$XIMIX_OUT" = "x" ]]; then
	XIMIX_OUT="/dev/null"
fi


# export JAVA_HOME=/path/to/java
# export XIMIX_HOME=/path/to/ximix


if [[ "x$JAVA_HOME" = "x" ]]; then
	echo "JAVA_HOME is not defined."
    exit -1
fi

if [[ "x$XIMIX_HOME" = "x" ]]; then
        echo "XIMIX_HOME is not defined."
        exit -1
fi


start() {
        echo "Starting Ximix Node $NODE"
        su $XIMIX_USER -c "$XIMIX_HOME/bin/start.sh $NODE 2>&1" > $XIMIX_OUT
}

stop() {
        su $XIMIX_USER -c "$XIMIX_HOME/bin/stop.sh $NODE"
}

case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  restart)
        stop
        start
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart}"
        exit 1
esac
exit 0

