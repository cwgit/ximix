#!/bin/bash

#
# chkconfig: 35 90 12
# description: Ximix Node
#


#
# The user to run ximix under.

if [[ "x$XIMIX_CONSOLE_USER" = "x" ]]; then
	XIMIX_CONSOLE_USER=ximix
fi


#
# Where to direct stdout and stderr
#
if [[ "x$XIMIX_CONSOLE_OUT" = "x" ]]; then
	XIMIX_CONSOLE_OUT="/dev/null"
fi


# export JAVA_HOME=
# export XIMIX_CONSOLE_HOME=


if [[ "x$JAVA_HOME" = "x" ]]; then
	echo "JAVA_HOME is not defined."
	exit -1
fi

if [[ "x$XIMIX_CONSOLE_HOME" = "x" ]]; then
        echo "XIMIX_CONSOLE_HOME is not defined."
	exit -1
fi



start() {
	echo "Starting Ximix Console."
	su $XIMIX_CONSOLE_USER -c "$XIMIX_CONSOLE_HOME/bin/start.sh $NODE 2>&1" > $XIMIX_CONSOLE_OUT
}

stop() {
	echo "Stopping Ximix Console"
	su $XIMIX_CONSOLE_USER -c "$XIMIX_CONSOLE_HOME/bin/stop.sh $NODE"
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

