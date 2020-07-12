# ZWave-Sniffer-Suite
this repository collects the Proof of Concept work on Wireshark extension tools for sniffing
an ZWave network on different levels:
1. Zniffer
Zniffer related tools rely on an ZMEUZB1 USB stick modified with the SILabs Zniffer firmware.
With this tools, the ZWave network could be sniffed on a raw ZWave packet level.
2. Serial API
This variant sniffs the communication between a ZWave controller and the host. 
This sniffing method allows the analysis of the ZWave network on an application level

# Usage
## Install
1. clone this repository
2. open Wireshark
3. open About Wireshark dialog
4. display Folders category in the About dialog
5. find paths for lua scripts and extcap plugins, prefered here the user specific paths.
6. Copy the dissector lua files from 
     dissectors/
    folder into the wireshark folder for LUA scripts (here the red one
    )
7. Copy the extcap pluging files from 
     extcap/
    folder into the wireshark folder for EXTCAP plugins (here the green one)
8. make the extcap plugins executable

## Zniffer variant
- Prerequisits: Zniffer extcap and dissectors installed, ZMEUZB1 with Zniffer firmware 2.55 connected
- open Wireshark
- configure Zniffer capture device, here set your serial device (ex. /dev/ttyACM0)
- start capturing with Zniffer capture device

## Serial API variant
- Prerequisits: SerialAPI extcap and dissectors installed, strace compatible Unix system 
- start zw-sapi-tap.py with your serial device as argument
- the zw-sapi-tap will tap the communication by sniffing all read/write syscalls for the file descriptor of your
opened ZWave device and will provide the data as a TCP server on port 4201.
- open wireshark
- configure ZWave Serial API sniffing device, here set the adress and port of the zw-sapi-tap server
- start sniffing

# Issues
- This work is based on reverse engineering the Zniffer serial communication. That means, not all protocol
information is known yet. 
- Sniffing crypted ZWave packets even with a known network key is not supported right now
- The Thread handling in the Extcaps is somehow buggy, here the extcaps are still running in the background after
stopping sniffing in Wireshark.
- Protocol dissection is not complete yet.