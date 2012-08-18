#! /usr/bin/env python
#
# Idle detector daemon
#
# Copyright 2012 Albin Kauffmann <albin.kauffmann@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Daemon monitoring the system and executing a command when idle.

This daemon has originally been written to suspend on RAM my personnal server
when unused. Thus, I am running it with the command `pm-suspend` but it could of
course be run with any other command.

As of this version, the daemon can monitor:
 * established network connections (see configuration below)
 * more comming (see TODO)

Monitoring established connections
==================================
The daemon is using netstat to list established connections (INET sockets only).
In order to monitor connections and avoid pooling netstat, iptables must be
configured to log INPUT and OUTPUT (and eventually FORWARD) connection
creations. This is done with the following commands:

sh> iptables -t filter -A INPUT -m state --state NEW -j LOG \\
    --log-prefix "idle-detector: INPUT "
sh> iptables -t filter -A OUTPUT -m state --state NEW -j LOG \\
    --log-prefix "idle-detector: OUTPUT "

Note that this can create a lot of logs in /var/log/kern.log, that's why this
program might not be suitable for computers serving lots of users. In order to
avoid strangers (hackers or pirates) to fill your hard drive, I recommend you to
add rules such as (these commands add the rules at the beginning of the INPUT
chain):

sh> iptables -t filter -I INPUT -m state --state NEW -m recent --name badguys \\
    --set
sh> iptables -t filter -I INPUT -m state --state NEW -m recent --name badguys \\
    --update --seconds 60 --hitcount 15 -j DROP

If you server is under attack (SSH brute force for example), it won't go to the
idle state. Then, you will have to increase the "seconds" value of the previous
iptables command or decrease the time this script waits before going to sleep.
"""

import sys
import getopt
import syslog
import subprocess
import re
import string
import pyinotify
import datetime


__author__ = "Albin Kauffmann <albin.kauffmann@gmail.com>"
__copyright__ = "Copyright 2012, Albin Kauffmann"
__license__ = "GPLv3"
__version__ = "git"


# Default values for optionnal options
opt_iptables_log = "/var/log/kern.log"
opt_iptables_log_pattern = "idle-detector"
opt_timeout = 10
opt_command = None

g_timeout = 0

def usage():
    """Print the usage and exit."""
    print sys.argv[0] + " [OPTIONS] COMMAND ARGS\n\
\n\
idle-detector allows to call COMMAND with its arguments after a period of\n\
inactivity (10 minutes by default).\n\
\n\
OPTIONS are:\n\
\t-t, --timeout=TIME\tset the idle time (minutes) (default %i)\n\
\t-h, --help\t\tdisplay this help and exit" % \
    (opt_timeout)
    exit(1)

def check_iptables_config():
    """Display a message in syslogs if no iptables rule is defined"""
    nb_rules = 0
    regexp = re.compile("LOG.*prefix \"%s\"" % opt_iptables_log_pattern)
    cmd = subprocess.Popen(["iptables", "-t", "filter", "-nvL"],
                           stdout=subprocess.PIPE)
    for line in cmd.stdout:
        if regexp.match(line):
            nb_rules += 1
    if nb_rules < 1:
        syslog.syslog(syslog.LOG_WARNING, "No iptables rules seem installed. \
Read the README for more informations")

class EventLogger(pyinotify.ProcessEvent):
    """Class allowing to monitor iptables logs (with inotify)"""

    __fd = None

    def __init__(self, filename):
        self.__fd = open(filename)
        self.__fd.seek(0, 2)

    def process_IN_MODIFY(self, event):
        global g_timeout
        line = self.__fd.readline()
        while line != "":
            if line.find(opt_iptables_log_pattern) >= 0:
                g_timeout = opt_timeout * 60 * 1000
            line = self.__fd.readline()

def wait_until_idle(notifier, timeout):
    """Waits until the system is idle for "timeout" minutes"""
    global g_timeout
    g_timeout = timeout * 60 * 1000
    notifier.process_events()
    time_start = datetime.datetime.now()
    while notifier.check_events(g_timeout):
        notifier.read_events()
        t = (datetime.datetime.now() - time_start).total_seconds() * 1000
        if t < g_timeout:
            g_timeout -= t
        notifier.process_events()
        time_start = datetime.datetime.now()

def nb_established_connections():
    """Returns the number of established connections returned by netstat"""
    p = subprocess.Popen(["netstat", "--protocol=inet"], stdout=subprocess.PIPE)
    i = 0
    for l in p.stdout:
        i += 1
    return i - 2

def main():
    try:
        (opts,args) = getopt.getopt(sys.argv[1:], "ht:", ["help", "timeout="])
    except getopt.error as msg:
        print msg
        print "Try '" + sys.argv[0] + " --help' for more information."
        exit(1)
    for (o, a) in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ("-t", "--timeout"):
            global opt_timeout
            opt_timeout = int(a)
    if (len(args) < 1):
        usage()
    global opt_command
    opt_command = string.join(args, " ")

    check_iptables_config()
    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, EventLogger(opt_iptables_log))
    wdd = wm.add_watch(opt_iptables_log, pyinotify.IN_MODIFY)

    nb_connec = nb_established_connections()
    while True:
        try:
            wait_until_idle(notifier, opt_timeout)
        except Exception as err:
            print err
            notifier.stop()
            exit(2)
        nb_connec_prev = nb_connec
        nb_connec = nb_established_connections()
        if (nb_connec_prev == 0) and (nb_connec == 0):
            syslog.syslog(syslog.LOG_INFO, "going to sleep")
            subprocess.call(opt_command, shell=True)

main()
