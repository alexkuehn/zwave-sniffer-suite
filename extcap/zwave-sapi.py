#!/usr/bin/env python3

# zwave-sapi
# extcap plugin for reading ZWave SerialAPI communication 
# 
# zwave-sapi.py
# provides an EXTCAP compatible API for integrating into wireshark
# it connects to an TCP socket, where the SerialAPI tap process provides
# SerialAPI communication sniffing packets
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

import logging
import argparse
import threading
import queue
import time
import enum
import binascii
import sys
import struct
import os
import socket

# extcap
ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3


# ZWave serial protocol semantic
DATAFRAME_BEGIN = 0x01
DATAFRAME_ACK = 0x06
DATAFRAME_NACK = 0x15
DATAFRAME_CAN = 0x18

def unsigned(n):
    return int(n) & 0xFFFFFFFF

# helper for displaying hex
byte2hex = lambda b: ' '.join('%02x' % i for i in b)

"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

### EXTCAP FUNCTIONALITY

def extcap_config(interface):

    if (interface == "zwsapi"):
        # Args
        # Capture Tab
        print("arg {number=0}{call=--tap-host}{display=Serial API Tap Host}{type=string}{tooltip=The remote host where Tap Server runs. It can be both an IP address or a hostname}{required=true}")
        print("arg {number=1}{call=--tap-port}{display=Serial API Tap port}{type=unsigned}{tooltip=The remote  tap host port (1-65535)}{range=1,65535}{default=4201}")

def extcap_version():
    print("extcap {version=1.0}")

def extcap_interfaces():
    print("extcap {version=1.0}")
    print("interface {value=zwsapi}{display=ZWave serial API sniffer}")

def extcap_dlts(interface):
    if (interface == "zwsapi"):
        print("dlt {number=148}{name=zwsapi}{display=ZWaver serial API sniffer uses User1 DLT}")

def extcap_capture(interface, taphost, tapport, fifo, capture_filter):
    if (interface == "zwsapi"):
        zwave = ZWaveSerialTap(taphost, tapport)
        zwave.startSniffer()
        
        if fifo is not None:
            with open(fifo, 'wb', 0) as fh:
                
                fh.write(gen_pcap_header())
                while True:
                    dataframe = zwave.getFrame()
                    if dataframe is not None:
                        fh.write(gen_pcap_package(dataframe))        
        else:
            while True:
                try:
                    dataframe = zwave.getFrame()
                    if dataframe is not None:
                        pass                        
                except KeyboardInterrupt:
                    break
        zwave.stopSniffer()
        zwave.shutdownSniffer()

def gen_pcap_header():
    header = bytearray()
    header += struct.pack('<L', int ('a1b2c3d4', 16 ))
    header += struct.pack('<H', unsigned(2) ) # Pcap Major Version
    header += struct.pack('<H', unsigned(4) ) # Pcap Minor Version
    header += struct.pack('<I', int(0)) # Timezone
    header += struct.pack('<I', int(0)) # Accurancy of timestamps
    header += struct.pack('<L', int ('0000ffff', 16 )) # Max Length of capture frame
    header += struct.pack('<L', unsigned(148)) # USER_1
    return header

def gen_pcap_package( dataframe ):
    print(dataframe[0])
    print(dataframe[1])
    print(dataframe[2])
    rawdata = bytearray()
    if dataframe[1] == True:
        rawdata += b'\x01'
    else:
        rawdata += b'\x00'
    if isinstance(dataframe[2], int) == True:
        rawdata.extend( struct.pack('B',dataframe[2]))
    else:
        rawdata += bytearray(dataframe[2])
    pcap = bytearray()
    caplength = len(rawdata)
    timestamp = int(dataframe[0])

    pcap += struct.pack('<L', unsigned(timestamp ) ) # timestamp seconds
    pcap += struct.pack('<L', 0x00  ) # timestamp nanoseconds
    pcap += struct.pack('<L', unsigned(caplength ) ) # length captured
    pcap += struct.pack('<L', unsigned(caplength ) ) # length in frame
    pcap += rawdata
    return pcap

# represents the Zniffer protocol state
class ZWaveProtocolState(enum.Enum):
    INIT = 0
    INFRAME = 1


# ZWave Serial class represents the ZWave serial tap control and acquisiton
class ZWaveSerialTap(object):
    # init the serial tap with defaults
    def __init__(self,taphost, tapport):       
        super().__init__()
        self.taphost = taphost
        self.tapport = tapport
        self.running = False
        self.protocolstate = ZWaveProtocolState.INIT        
        self.protogarbage = []
        
    

    # get data from frame queue
    def getFrame(self):
        try:
            data = self.framequeue.get(block=True,timeout=1)
        except queue.Empty:
            data = None
        return data

    # Zniffing process
    def sniff(self):
        logmod = logging.getLogger('SerialTap')
        # run until flag is taken down or serial connection has error 
        while self.running:
            try:
                # get data
                data = self.socketfile.readline()
                # check if data available, then process 
                if len(data) > 0:
                    logmod.debug("Data: %s", data)                    
                    self.parseSniff(data)
            except:
                break
    
    def parseSniff(self, data):
        logmod = logging.getLogger('TapParser')
        logmod.info('Entry State: %s', self.protocolstate)
        
        # first split up data
        splitdata = data.split(':', 4)
        timestr = splitdata[0] + ':' + splitdata[1] + ':' + splitdata[2]
        dirstr = splitdata[3]
        databytes = bytearray.fromhex(splitdata[4])

        if dirstr == 'w':
            framedirsend = True
        else:
            framedirsend = False

        # wait for protocol frame
        if self.protocolstate == ZWaveProtocolState.INIT:
            
            # frame start detected
            if databytes[0] == DATAFRAME_BEGIN:
                # store direction
                self.framesend = framedirsend
                self.frametime = time.time()

                self.protocolstate = ZWaveProtocolState.INFRAME
                # check if we had some garbage data in the buffer and clean it for further data
                if len(self.protogarbage) > 0:
                    logmod.info('garbage received: %s' % (byte2hex(self.protogarbage)) )
                    self.protogarbage.clear()

                # clean the frame input buffer and add the remaining bytes of the queue
                self.framebuffer = []
                self.framelength = 0
                self.framebuffer.extend(databytes) 

                # check if we already have some length information
                if len(self.framebuffer) > 1:
                    # length is second byte, we expect one more for checksum
                    self.framelength = self.framebuffer[1] + 2
                
                    # plausibility check, is our input longer, then we should reinit
                    if( len(self.framebuffer) > self.framelength):
                        logmod.info('frame longer than expected: %d - %d' % (len(self.framebuffer), self.framelength))
                        self.protocolstate = ZWaveProtocolState.INIT
                    # check if we already have all data
                    if( len(self.framebuffer) == self.framelength):
                        logmod.info('frame received on one block')
                        self.framequeue.put( (self.frametime,self.framesend, self.framebuffer))
                        self.protocolstate = ZWaveProtocolState.INIT
            elif databytes[0] == DATAFRAME_ACK or databytes[0] == DATAFRAME_NACK or databytes[0] == DATAFRAME_CAN:
                self.protocolstate = ZWaveProtocolState.INIT
                self.frametime = time.time()
                self.framequeue.put( (self.frametime, framedirsend, databytes[0]))
                    
            # otherwise store in garbage buffer for further handling
            else:                
                self.protogarbage.extend(databytes)

        # parser in Frame consuming
        elif self.protocolstate == ZWaveProtocolState.INFRAME:
            # check if there is more data transfer in the same direction, this is potential frame data
            # if the direction changed, it could be an ACK/NACK
            if framedirsend != self.framesend:
                if databytes[0] == DATAFRAME_ACK or databytes[0] == DATAFRAME_NACK or databytes[0] == DATAFRAME_CAN:
                    self.protocolstate = ZWaveProtocolState.INIT
                    self.frametime = time.time()
                    self.framequeue.put( (self.frametime, framedirsend, databytes[0]))
            else:
                self.framebuffer.extend(databytes)
                # check if we have enough length information
                if len(self.framebuffer) > 1:
                    # length is second byte, we expect one more for checksum
                    self.framelength = self.framebuffer[1] + 2
                # plausibility check, is our input longer, then we should reinit
                if( len(self.framebuffer) > self.framelength):
                    logmod.info('frame longer than expected: %d - %d' % (len(self.framebuffer), self.framelength))
                    self.protocolstate = ZWaveProtocolState.INIT
                # check if we already have all data
                if( len(self.framebuffer) == self.framelength):
                    logmod.info('frame fully received')
                    self.framequeue.put( (self.frametime,self.framesend, self.framebuffer))
                    self.protocolstate = ZWaveProtocolState.INIT

          
        else:
            logmod.info("Unknown Protocol State")

        logmod.info('Exit State: %s', self.protocolstate)
            
    # start the Sniffing process
    def startSniffer(self): 
        logmod = logging.getLogger('SerialTap')
        # connect to socket
        self.socketconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socketconn.connect((self.taphost, self.tapport))
        # make file out of socket
        self.socketfile = self.socketconn.makefile()
    
        # init protocol state machine and start the sniffing thread
        self.running = True
        self.protocolstate = ZWaveProtocolState.INIT
        self.tapthread = threading.Thread(target=self.sniff)
        self.tapthread.start()
        self.framequeue = queue.Queue()

    # stop the sniffing process
    def stopSniffer(self):        
        logmod = logging.getLogger('SerialTap')
        # take down running flag and wait for thread leaving
        if self.running:
            self.running = False
            self.tapthread.join()
    
    # close the sniffer
    def shutdownSniffer(self):
        self.socketfile.close()
        self.running = False

def usage():
    print("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0])


def execZwSniffer():
    # setup command line
    parser = argparse.ArgumentParser(description='tap ZWave communication with ZWave serial tap helper daemon')
    parser.add_argument('-v', '--verbose', dest='verbosity', action='count',
                        help='print more diagnostic messages (option can be given multiple times', default=0)
    parser.add_argument("--capture", help="Start the capture routine", action="store_true")
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface",
                        action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")

   # Interface Arguments
    parser.add_argument("--tap-host", help="the tapping host" )
    parser.add_argument("--tap-port", help="the tapping port", type=int, default=4201)

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print("%s: %s" % (exc.argument.dest, exc.message), file=sys.stderr)
        sys.exit(ERROR_ARG)

    # determine loglevel out of verbosity argument
    if args.verbosity > 3:
        args.verbosity = 3
    loglevel = (logging.WARNING,
                logging.INFO,
                logging.DEBUG,
                logging.NOTSET)[args.verbosity]
    logging.basicConfig(level=loglevel)
    logging.info('ZWave Sniffer started')

    if ( args.extcap_version and not args.extcap_interfaces ):
        extcap_version()
        sys.exit(0)

    if ( args.extcap_interfaces == False and args.extcap_interface == None ):
        parser.exit("An interface must be provided or the selection must be displayed")
    if ( args.extcap_interfaces == True or args.extcap_interface == None ):
        extcap_interfaces()
        sys.exit(0)

    if args.extcap_config:
        extcap_config(args.extcap_interface)
    elif args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
    elif args.capture:
        if (args.extcap_interface == "zwsapi"):
            extcap_capture(args.extcap_interface, args.tap_host, args.tap_port, args.fifo, args.extcap_capture_filter)
        else:
            sys.exit(ERROR_INTERFACE)
    else:
        usage()
        sys.exit(ERROR_USAGE)



if __name__ == '__main__':
    execZwSniffer()