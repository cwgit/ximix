#!/bin/bash

if [[ -z "$XIMXI_CONSOLE_HOME" ]]; then
        L=`dirname $0`
        XIMIX_CONSOLE_HOME="$L/../"

fi

if [[ ! -d "$XIMIX_CONSOLE_HOME/libs" ]]; then
        echo "Could not find libs directory off XIMIX_CONSOLE_HOME ( $XIMIX_CONSOLE_HOME )"
        exit -1
fi

PIDFILE="$XIMIX_CONSOLE_HOME/console.pid"

if [[ ! -f "$PIDFILE" ]]; then
	echo "Pid file not found: $PIDFILE";
	exit -1;
fi

PID=`cat $PIDFILE`

if ps -p $PID > /dev/null; then
COUNTER=12
until [  $COUNTER -lt 0 ]; do
	echo "Sending kill -15 to Console ($PID)"
	kill -15 $PID
	sleep 5;
	let COUNTER-=1
	if ps -p $PID >/dev/null; then
	continue;
	fi
	echo "Stopped node $1";
	exit 0;
done

echo "$1 not respoding to kill -15, sending kill -9"

kill -9 $PID
else
echo "Console with pid $PID is not running."
fi
