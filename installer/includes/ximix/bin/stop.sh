#!/bin/bash

if [[ -z "$XIMXI_HOME" ]]; then
        L=`dirname $0`
        XIMIX_HOME="$L/../"

fi

if [[ "x$1" = "x" ]]; then
        echo "Parameter 1 must be node name, eg stop.sh node1"
        exit -1
fi

if [[ ! -d "$XIMIX_HOME/libs" ]]; then
        echo "Could not find libs directory off XIMIX_HOME ( $XIMIX_HOME )"
        exit -1
fi

PIDFILE="$XIMIX_HOME/$1/$1.pid"

if [[ ! -f "$PIDFILE" ]]; then
	echo "Pid file not found: $PIDFILE";
	exit -1;
fi

PID=`cat $PIDFILE`

if ps -p $PID > /dev/null; then
COUNTER=12
until [  $COUNTER -lt 0 ]; do
	echo "Sending kill -15 to $1 ($PID)"
	kill -15 $PID
	sleep 5;
	let COUNTER-=1
	if ps -p $PID >/dev/null; then
	continue;
	fi
	echo "Stopped node $1";
	exit 0;
done

echo "$1 not responding to kill -15, sending kill -9"

kill -9 $PID
else
    echo "$1 with pid $PID is not running."
fi

