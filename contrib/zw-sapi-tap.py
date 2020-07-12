#!/usr/bin/env python3

# zw-sapi-tap
# tool  for tapping the communication with a ZWave controller over SerialAPI
# 
# zw-sapi-tap.py
# taps the communication with the ZWave controller 
# this is realized with strace, which grabs the read and write on serial file descriptor
# the result is provided on a TCP socket in the follwoing format
#   <timestamp>:<direction>:<hex data>
#
# Copyright C) 2020 Alexander Kühn <prj@alexkuehn.de>
# 
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Lesser Public License for more
# details.
# 
# You should have received a copy of the GNU Lesser General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import subprocess
import argparse
import sys
import threading
import time
import shlex
import queue
import socket
import logging



 
class TracerTap(object):
    def __init__(self, devicename):
        self.tapdevice = devicename 
        self.paused = True
        self.msgqueue = queue.Queue()
        self.tracethread = None
        self.commthread = None
    
    def get_queue(self):
        return self.msgqueue

    def pause(self, state):
        self.paused = state

    def stop(self, false):
        self.alive = False
        self.tracethread.join()

    def start(self):
        # find the attached PID and file descriptor
        self.procinfo = self.get_procinfo(self.tapdevice)
        
        if self.procinfo != None:
            self.fid = int(self.procinfo[1])
            self.pid = int(self.procinfo[0])
            logging.debug("tapping process: %d with file descriptor %d" % (self.pid, self.fid))
            # attached process found
            # now start the sniffing process with strace
            cmd="strace -s 1000 -qq -xx -tt -e trace=read,write -e signal=none -e read=%d -e write=%d -fp %d" % (self.fid, self.fid, self.pid)
            sproc = subprocess.Popen(shlex.split(cmd),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
            
            self.tracethread = threading.Thread(target=self.strace_reader, args=(sproc,))
            self.alive = True
            self.tracethread.start()
        else:
            # we didn't find an attached process
            logging.warn("couldn't determine file descriptor for serial device %s" % self.tapdevice)


    def get_procinfo(self, devstring):
        # find the attached process to the serial device with help of lsof unix command
        lsof = subprocess.check_output( ('lsof', '-Ff', args.devicename))

        # parse the lsof output for attached process id and file descriptor
        lines = lsof.decode().split('\n')
        pid = None
        fid = None
        for l in lines:
            if l.startswith('p'):
                pid = l[1:]
            if l.startswith('f'):
                fid = l[1:]
        # build a tuple with the (pid,fd) information
        procinfo = None
        if fid != None and pid != None:
            procinfo = (pid, fid)
        return procinfo

    def strace_reader(self, proc):
        logging.info("strace connected")
        while True:
            output = proc.stdout.readline()
            if output == '' and proc.poll() is not None and self.alive==False:
                break
            if output:                
                result = self.parse_trace(output,self.fid)
                if result != None:
                    logging.debug( "message time: %s, direction %s, data %s" % result)
                    if self.paused == False:
                        self.msgqueue.put(result)

        
    def parse_trace(self, cmdout, fid):
        result = None
        cmdstring = cmdout.decode('utf-8') 
        if cmdstring.find("read(") >= 0:
            mode = 'r'
            splitstring = "read("
        elif cmdstring.find("write(") >= 0:
            mode = 'w'
            splitstring="write("
        else:
            mode = None
        
        if mode is not None:
            argstr = cmdstring.split(splitstring,1)
            actfid = int(argstr[1].split(',')[0])
            if actfid == fid:
                timestamp = argstr[0].split(']')[1].strip()
                try:                  
                    datastr = argstr[1].split('\"')[1]
                    datastrlist = datastr.split("\\x")[1:]
                    datanum = [int(i,16) for i in datastrlist]
                    datarepr = "".join([ "%02X " % i for i in datanum])
                    result = (timestamp, mode, datarepr)                
                except IndexError as error:
                    result = None
                    logging.warn( "unparsable: %s" % cmdstring)
        return result

    def route( self, conn ):
        self.pause( False)
        while True:
            msg = self.msgqueue.get()
            sendstr = "%s:%s:%s\n" % msg
            conn.sendall( sendstr.encode('utf-8'))

if __name__ == "__main__":
    # setup command line arguments, we need the device where we want to attach
    parser = argparse.ArgumentParser(description='tap the process occupying the serial device "device" and routes the data to a socket')
    parser.add_argument('devicename', metavar='device', help='serial device for sniffing')
    parser.add_argument('-p', '--port', type=int, dest='tcpport', help='socket port for tapped messages', default=4201)
    parser.add_argument( '-v', '--verbose', dest='verbosity', action='count',
                            help='print more diagnostic messages (option can be given multiple times)',
                            default=0)
                        
    args = parser.parse_args()

    # determine loglevel<
    if args.verbosity > 3:
        args.verbosity =3
    loglevel = (logging.WARNING,
             logging.INFO,
             logging.DEBUG,
             logging.NOTSET)[args.verbosity]
    logging.basicConfig(level=loglevel)
    logging.info("ZWave Serial API Tap started")
    
    tap = TracerTap(args.devicename)
    # start the tapping process
    tap.start()

    # start the socket server, only one connection
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('', args.tcpport))
    srv.listen(1)
    logging.info("TCP server started on port: {}".format(args.tcpport))

    while True:
        try:
            client_socket, addr = srv.accept()
            logging.info('TCP client connected {}:{}'.format(addr[0], addr[1]))
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            try:
                tap.route( client_socket )    
            finally:
                logging.info('Disconnected')
                tap.pause(True)
                client_socket.close()                
        except KeyboardInterrupt:
            tap.stop()
            break
        except socket.error as msg:
            logging.error(str(msg))


