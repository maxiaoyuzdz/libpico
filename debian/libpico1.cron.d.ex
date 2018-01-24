#
# Regular cron jobs for the libpico-0.0 package
#
0 4	* * *	root	[ -x /usr/bin/libpico-0.0_maintenance ] && /usr/bin/libpico-0.0_maintenance
