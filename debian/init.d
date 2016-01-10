#!/bin/sh
#
# /etc/init.d/xplico  --  start/stop the Xplico daemon. Xplico will decode the capture you upload to its web interface (default http://localhost:9876)
# 
### BEGIN INIT INFO
# Provides:          Xplico
# Required-Start:    $syslog $network $apache2
# Required-Stop:     $syslog
# Should-Start:      $local_fs
# Should-Stop:       $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Starts and stops the xplico daemon
### END INIT INFO

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/opt/xplico/bin

NAME="Xplico"
DAEMON=/opt/xplico/bin/dema
#APPLICATION=/opt/xplico/bin/dema
PIDFILE=/var/run/dema.pid
APACHEPIDFILE1=/var/run/apache2.pid
APACHEPIDFILE2=/var/run/apache2/apache2.pid

DESC=""
RUN_DAEMON=yes
PRIORITY=1 #(0..20)
  #0: don't change priority
  #1: better priority
  #...
  #20: highest priority, not recommended.


#INTERFACE=eth1
#CONFIG_FILE="/opt/xplico/cfg/xplico.cfg"
#MODE=pcap
#PATH_DECODED_FILES="/opt/xplico/bin/"

#DAEMON_ARGS="-c $CONFIG_FILE -m $MODE -i $INTERFACE"
#DAEMON_ARGS=""



unset LANG
trap "" 1 15

test -x $DAEMON || exit 0
run_xplico="1"



if [ "x$RUN_DAEMON" = "xno" ]; then
    run_xplico=0
fi


is_running() 
{
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
		|| return 0
	return 1
}


is_apache2_running() 
{
	PIDS=`pidof apache2` || true  # Array of Apache forks.

	[ -e $APACHEPIDFILE1 ] && PIDS2=`cat $APACHEPIDFILE1` #Last Apache2 pid known.
	[ -e $APACHEPIDFILE2 ] && PIDS2=`cat $APACHEPIDFILE2` #Last Apache2 pid known.
	# if there is a pid we need to verify that belongs to apache2 
	for i in $PIDS; do
	  if [ "$i" = "$PIDS2" ]; then
            # in this case the pid stored in the pidfile matches one of the pidof apache
            #echo $i
            return 0
	  fi
	done
	echo "  Error, Apache2 not running"
	return 1
}

# Function that starts the daemon/service
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started

	

	#Check Apache2 is up&running
	is_apache2_running || return 2

	is_running
	


	case "$?" in
		0) echo "Xplico was (and is) already running" ;; 
		1) # ulimit
		   ulimit -n 200000
		   ulimit -m unlimited
		   #ulimit -u unlimited #this is a value for bash, not sh.
		   ulimit -v unlimited
		   # kill  : Not necessary here, will use the function  "is_running"
		   #killall dema
		   # start dema
		  (cd /opt/xplico/bin; ./dema -d /opt/xplico -b sqlite > /dev/null) &
		  #Optional: let's give more priotity and CPU to xplico, so decoding will be faster.
		  
		  if [ "$PRIORITY" -ge "0" ] && [ "$PRIORITY" -le "20" ]; then
		    if [ "$PRIORITY" -ge "1" ]; then 
		      echo Modifying priority to -$PRIORITY
		      sleep 1  #giving time to DEMA to start and write its pid in the PIDFILE
		      renice -$PRIORITY `cat $PIDFILE`  >> /dev/null
		    #else: "PRIORITY is 0, nothing will be done.
		    fi
		  else
		    echo "WARNING: Xplico priority not altered: wrong priority value (check $PRIORITY, range 0..20, default:0)"
		  fi
		  ;;

		*) echo "Error #123" ;; # Failed to start
	esac
}


# Function that stops the daemon/service
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	
	start-stop-daemon --stop --quiet --retry=TERM/10/KILL/2 --pidfile $PIDFILE 
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec $DAEMON
	[ "$?" = 2 ] && return 2
#	killall -9 dema
	return "$RETVAL"
}

. /lib/lsb/init-functions

case "$1" in
    start)
        if [ "$run_xplico" = "1" ]; then
					[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
					do_start
					case "$?" in
						0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
						2)   [ "$VERBOSE" != no ] && log_end_msg 1 ;; 
					esac
        fi
	echo
        ;;
    stop)
       # if [ -f /var/run/xplico.pid ] && kill -0 `cat /var/run/xplico.pid` 2>/dev/null; then
					[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
					do_stop
					case "$?" in
						0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
						2)   [ "$VERBOSE" != no ] && log_end_msg 1 ;;
					esac
        # fi
        ;;
    restart|force-reload)
        if [ "$run_xplico" = "1" ]; then
					log_daemon_msg "Restarting $DESC" "$NAME"
					do_stop
					case "$?" in
						0|1)
						do_start
						case "$?" in
							0) log_end_msg 0 ;;
							1) log_end_msg 1 ;; # Old process is still running
							*) log_end_msg 1 ;; # Failed to start
						esac
						;;
						*)
							# Failed to stop
						log_end_msg 1
						;;
					esac
        fi
        ;;
		status)
			if is_running; then
				log_success_msg "Xplico web interface IS RUNNING to decode traffic capture files"
				exit 0
			else
				log_failure_msg "Xplico web interface mode is not running."
				exit 1
			fi
			;;				
    *)
        echo "Usage: /etc/init.d/xplico {start|stop|restart|force-reload|status}"
        exit 1
        ;;
esac

exit 0
