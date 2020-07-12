#!/usr/bin/env python3

# zwave-zniffer
# extcap plugin for reading ZWave Zniffer communication
# 
# zwave-zniffer.py
# provides an EXTCAP compatible API for integrating into wireshark
# it connects to an USB ZMEEUZBB with Zniffer firmware 2.55 over virtual serial port
# and sniffs the ZWave raw packets
# the low level serial protocol is handled here
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

import serial
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
import datetime
# extcap
ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3


# default serial config
SERIAL_SPEED = 230400

# Zniffer protocol semantic
ZNIFF_PACKET_BEGIN = 0x21
ZNIFF_FRAME_PACKET = 0x01
ZNIFF_FRAME_WAKESTART = 0x04
ZNIFF_FRAME_WAKESTOP = 0x05

# data frame header length
ZNIFF_FRAME_PACKET_LENGTHCOUNT = 7
# WakeStart frame header length
# TODO: very hacky, WakeStart packets vary in length, so we will see live if frame is shorter
ZNIFF_FRAME_WAKESTART_LENGTH = 9
# WakeStop frame header length
ZNIFF_FRAME_WAKESTOP_LENGTH = 5

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

    if (interface == "zniffer"):
        # Args
        # Capture Tab
        print("arg {number=0}{call=--device}{display=Device}{type=string}{tooltip=Serial Device}")

def extcap_version():
    print("extcap {version=1.0}")

def extcap_interfaces():
    print("extcap {version=1.0}")
    print("interface {value=zniffer}{display=Zniffer ZWave sniffer}")

def extcap_dlts(interface):
    if (interface == "zniffer"):
        print("dlt {number=147}{name=zniffer}{display=Zniffer uses User0 DLT}")

def extcap_capture(interface, device, fifo, capture_filter):
    if (interface == "zniffer"):
        znifferdev = Zniffer(device)
        znifferdev.initZniffer()
        znifferdev.startZniffer()
        
        if fifo is not None:
            with open(fifo, 'wb', 0) as fh:
                
                fh.write(gen_pcap_header())
                while True:
                    dataframe = znifferdev.getFrame()
                    if dataframe is not None:
                        fh.write(gen_pcap_package(dataframe))        
        else:
            while True:
                try:
                    dataframe = znifferdev.getFrame()
                    if dataframe is not None:
                        pass
                        print(dataframe)
                except KeyboardInterrupt:
                    break
        znifferdev.stopZniffer()
        znifferdev.shutdownZniffer()

def gen_pcap_header():
    header = bytearray()
    header += struct.pack('<L', int ('a1b2c3d4', 16 ))
    header += struct.pack('<H', unsigned(2) ) # Pcap Major Version
    header += struct.pack('<H', unsigned(4) ) # Pcap Minor Version
    header += struct.pack('<I', int(0)) # Timezone
    header += struct.pack('<I', int(0)) # Accuracy of timestamps
    header += struct.pack('<L', int ('0000ffff', 16 )) # Max Length of capture frame
    header += struct.pack('<L', unsigned(147)) # USER_0
    return header

def gen_pcap_package( dataframe ):
    rawdata = [dataframe[0]]
    rawdata.extend(dataframe[2])
    pkt = bytearray(rawdata)
    pcap = bytearray()
    caplength = len(pkt)
    timestampsec = int(dataframe[1])
    ts = datetime.datetime.fromtimestamp(dataframe[1])
    timestampusec = ts.microsecond

    pcap += struct.pack('<L', unsigned(timestampsec ) ) # timestamp seconds
    pcap += struct.pack('<L', timestampusec ) # timestamp nanoseconds
    pcap += struct.pack('<L', unsigned(caplength ) ) # length captured
    pcap += struct.pack('<L', unsigned(caplength ) ) # length in frame
    pcap += pkt
    return pcap

# represents the Zniffer protocol state
class ZnifferProtocolState(enum.Enum):
    INIT = 0
    FRAME = 1
    PROCESS_PACKET = 2
    PROCESS_WAKESTART = 3
    PROCESS_WAKESTOP = 4
    PROCESS_PACKET_CONSUME = 5
    PROCESS_WAKESTART_CONSUME = 6
    PROCESS_WAKESTOP_CONSUME = 7
    PROCESS_UNKNOWN = 8
    PROCESS_UNKNOWN_END = 9


# Zniffer class represents the Zniffer control and acquisiton
class Zniffer(object):
    # init the Zniffer with defaults
    def __init__(self,znifferdevice):       
        super().__init__()
        self.serialthread = None
        self.serialhandle = serial.Serial( znifferdevice, SERIAL_SPEED, timeout=1)        
        self.running = False
        self.protocolstate = ZnifferProtocolState.INIT
        self.protogarbage = []
        self.protounknown = []
        

        
    # send serial data synchronously 
    def sendSync(self, data ):        
        self.serialhandle.write( data )
        rdata = self.serialhandle.read(128)
        return rdata
    
    # init the Zniffer stick
    def initZniffer(self):
        logmod = logging.getLogger('SerialCtrl')

        # TODO: this method is a static sequence for the purpose of a PoC
        #   a handshake implementation with also selecting the country/radio config is missing here
        r= self.sendSync( b'\x23\x05\x00\x49\x47')
        logmod.debug('reply to Seq1: %s', (byte2hex(r)))
        r= self.sendSync( b'\x23\x01\x00')
        logmod.debug('reply to Seq2: %s', (byte2hex(r)))
        r= self.sendSync( b'\x23\x0e\x01\x01')
        logmod.debug('reply to Seq3: %s', (byte2hex(r)))
        r= self.sendSync( b'\x23\x02\x01\x00')
        logmod.debug('reply to Seq4: %s', (byte2hex(r)))
        r= self.sendSync( b'\x23\x03\x00')
        logmod.debug('reply to Seq5: %s', (byte2hex(r)))

    # get data from frame queue
    def getFrame(self):
        try:
            data = self.framequeue.get(block=True,timeout=1)
        except queue.Empty:
            data = None
        return data

    # Zniffing process
    def zniff(self):
        logmod = logging.getLogger('SerialProc')
        # run until flag is taken down or serial connection has error 
        while self.running:
            try:
                # get data
                data = self.serialhandle.read()
                # check if data available, then process 
                if len(data) > 0:
                    logmod.debug("Data: %s", (byte2hex(data)))
                    self.parseZniff(ord(data))
            except:
                break
        self.running = False
        self.stopZniffer()
    
    def parseZniff(self, data):
        logmod = logging.getLogger('SerialParser')
        logmod.info('Entry State: %s', self.protocolstate)
        
        # wait for protocol frame
        if self.protocolstate == ZnifferProtocolState.INIT:
            
            # frame start detected
            if data == ZNIFF_PACKET_BEGIN:
                self.frametime = time.time()
                self.protocolstate = ZnifferProtocolState.FRAME
                # check if we had some garbage data in the buffer and clean it for further data
                if len(self.protogarbage) > 0:
                    logmod.info('garbage received: %s' % (byte2hex(self.protogarbage)))
                    self.protogarbage.clear()
            # otherwise store in garbage buffer for further handling
            else:                
                self.protogarbage.append(data)

        # parser in Frame consuming
        elif self.protocolstate == ZnifferProtocolState.FRAME:
            # reset element buffers and data counter
            self.protocount = 0
            self.protobuff = []

            # detect known packet formats and switch state accordingly
            if data == ZNIFF_FRAME_PACKET:            
                self.protocolstate = ZnifferProtocolState.PROCESS_PACKET                
            elif data == ZNIFF_FRAME_WAKESTART:
                self.protocolstate = ZnifferProtocolState.PROCESS_WAKESTART
            elif data == ZNIFF_FRAME_WAKESTOP:
                self.protocolstate = ZnifferProtocolState.PROCESS_WAKESTOP
            # TODO: hacky, Frame with unknown data content, store a new buffer until next plausible frame comes
            else:
                self.protounknown.append(data)
                self.protocolstate = ZnifferProtocolState.PROCESS_UNKNOWN
        
        # processing unknown frame
        elif self.protocolstate == ZnifferProtocolState.PROCESS_UNKNOWN:
            self.protocount = self.protocount + 1
            if data == ZNIFF_PACKET_BEGIN:
                # potential begin of a new frame, store the data temporary until next cycle
                self.protounknown_temp = data
                self.protocolstate = ZnifferProtocolState.PROCESS_UNKNOWN_END
            else:
                self.protounknown.append(data)

            if self.protocount > 255:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.INIT

        elif self.protocolstate == ZnifferProtocolState.PROCESS_UNKNOWN_END:
            self.protocount = self.protocount + 1
            # detect known packet formats and switch state accordingly
            if data == ZNIFF_FRAME_PACKET:            
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.PROCESS_PACKET                
                self.protocount = 0
                self.protobuff = []

            elif data == ZNIFF_FRAME_WAKESTART:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.PROCESS_WAKESTART
                self.protocount = 0
                self.protobuff = []
            elif data == ZNIFF_FRAME_WAKESTOP:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.PROCESS_WAKESTOP                
                self.protocount = 0
                self.protobuff = []
            else:
                # we expected a new frame,but this wasnt the case
                # reappend data
                self.protounknown.append(self.protounknown_temp)
                self.protounknown.append(data)
                self.protocolstate = ZnifferProtocolState.PROCESS_UNKNOWN

            if self.protocount > 255:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.INIT



                        
        # detected data packet
        elif self.protocolstate == ZnifferProtocolState.PROCESS_PACKET:
            
            self.protobuff.append(data)
            # consume in protocol until the data frame length field is reached             
            if self.protocount == ZNIFF_FRAME_PACKET_LENGTHCOUNT:
                self.dataframelength = data
                self.dataframe = []
                self.protocolstate = ZnifferProtocolState.PROCESS_PACKET_CONSUME
                logging.debug("Dataframe length: %d" % self.dataframelength)
            self.protocount = self.protocount + 1

        # consume dynamic data length data frame             
        elif self.protocolstate == ZnifferProtocolState.PROCESS_PACKET_CONSUME:
            # append to data buffer            
            self.dataframe.append(data)
            self.dataframelength = self.dataframelength - 1
            # when we reached the length, process the packet and reset the protol state machine
            if self.dataframelength == 0:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.INIT

        # detected WakeStart packet                
        elif self.protocolstate == ZnifferProtocolState.PROCESS_WAKESTART:
            # append to data buffer
            self.protobuff.append(data)
            self.protocount = self.protocount + 1
            # TODO: dirty trick for dynamic protocol length:
            if self.protocount == ZNIFF_FRAME_WAKESTART_LENGTH-1:
                if data  == 0x00:
                    self.processPacket()
                    self.protocolstate = ZnifferProtocolState.INIT
            # when we reached the length, process the packet and reset the protol state machine
            if self.protocount >= ZNIFF_FRAME_WAKESTART_LENGTH:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.INIT

        # detected WakeStop packet
        elif self.protocolstate == ZnifferProtocolState.PROCESS_WAKESTOP:
            # append to data buffer
            self.protobuff.append(data)
            self.protocount = self.protocount + 1
            # when we reached the length, process the packet and reset the protol state machine
            if self.protocount >= ZNIFF_FRAME_WAKESTOP_LENGTH:
                self.processPacket()
                self.protocolstate = ZnifferProtocolState.INIT        
        else:
            logmod.info("Unknown Protocol State")
            pass
        logmod.info('Exit State: %s', self.protocolstate)

    # process received packages
    def processPacket(self):
        logmod = logging.getLogger('ZWProtocol')
        # dependendant on the protocol state machine, handle different processing
        if self.protocolstate == ZnifferProtocolState.PROCESS_PACKET_CONSUME:
            logmod.debug('@%f Data Frame Header: %s' % (self.frametime, byte2hex(self.protobuff)))
            logmod.debug('Data Frame Content: %s' % (byte2hex(self.dataframe)))
            self.protobuff.extend(self.dataframe)
            self.framequeue.put( (ZNIFF_FRAME_PACKET, self.frametime, self.protobuff))
        if self.protocolstate == ZnifferProtocolState.PROCESS_WAKESTART:
            logmod.debug('@%f WakeStart Frame: %s'% (self.frametime, byte2hex(self.protobuff)))
            self.framequeue.put( (ZNIFF_FRAME_WAKESTART, self.frametime, self.protobuff))
        if self.protocolstate == ZnifferProtocolState.PROCESS_WAKESTOP:
            logmod.debug('@%f WakeStop Frame: %s'% (self.frametime, byte2hex(self.protobuff)))
            self.framequeue.put( (ZNIFF_FRAME_WAKESTOP, self.frametime, self.protobuff))
        if self.protocolstate == ZnifferProtocolState.PROCESS_UNKNOWN:
            logmod.debug('@%f Unknown Frame: %s'% (self.frametime, byte2hex(self.protounknown)))
            self.framequeue.put( (0xFF, self.frametime, self.protounknown))
        if self.protocolstate == ZnifferProtocolState.PROCESS_UNKNOWN_END:
            logmod.debug('@%f Unknown Frame: %s'% (self.frametime, byte2hex(self.protounknown)))
            self.framequeue.put( (0xFF, self.frametime, self.protounknown))
            
    # start the sniffing process
    def startZniffer(self): 
        logmod = logging.getLogger('SerialCtrl')
        # send start sniffing sequence to device
        r= self.sendSync( b'\x23\x04\x00')
        logmod.debug('reply to Seq: %s', (byte2hex(r)))
        # init protocol state machine and start the sniffing thread
        self.running = True
        self.protocolstate = ZnifferProtocolState.INIT
        self.serialthread = threading.Thread(target=self.zniff)
        self.serialthread.start()
        self.framequeue = queue.Queue()

    # stop the sniffing process
    def stopZniffer(self):        
        logmod = logging.getLogger('SerialCtrl')
        # send stop sniffing sequence 
        r = self.sendSync( b'\x23\x05\x00')
        logmod.debug('reply to Seq: %s', (byte2hex(r)))
        # take down running flag and wait for thread leaving
        if self.running:
            self.running = False
            self.serialthread.join()
    
    # close the sniffer
    def shutdownZniffer(self):
        self.serialhandle.close()
        self.serialhandle = None
        self.running = False

def usage():
    print("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0])


def execZwSniffer():
    # setup command line
    parser = argparse.ArgumentParser(description='tap ZWave communication with ZMEEUSB stick with Zniffer firmware')
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

    parser.add_argument("--device", help="sniffing device")

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
        if (args.extcap_interface == "zniffer"):
            extcap_capture(args.extcap_interface, args.device, args.fifo, args.extcap_capture_filter)
        else:
            sys.exit(ERROR_INTERFACE)
    else:
        usage()
        sys.exit(ERROR_USAGE)



if __name__ == '__main__':
    execZwSniffer()