# Zniffer Serial Protocol
## Environment
- ZMEEUZBB with Zniffer firmware 2.55
- Zniffer stick handled as serial modem
## Protocol
All values Hex
### Initialization
1. open with 115200 Baud
2. sequence
| send              | receive               | comment                                   |
| -----             | ---------             | ---------                                 |
| 23 05 00 49 47    | 23 05 00              | reset command                             |
| 23 01 00          | 23 01 04 05 00 02 37  | FW version?                               |
| 23 02 01 00       | 23 02 00              | 00=frequency band out of frequency table  |
| 23 03 00          | 23 03 18 00 00 01...  | frequency table entries list              |
| 23 13 01 00       | 23 03 04 00 02 45 55  | frequency table entry                     |
| 23 13 01 xx       | 23 03 xx yy zz        | frequency table entry                     |
3. close and reopen with 115200 Baud
4. sequence
| send              | receive               | comment                                   |
| -----             | ---------             | ---------                                 |
| 23 05 00 49 47    | 23 05 00              | reset command                             |
| 23 01 00          | 23 01 04 05 00 02 37  | FW version?                               |
| 23 02 01 00       | 23 02 00              | 00=frequency band out of frequency table  |
| 23 03 00          | 23 03 18 00 00 01...  | frequency table entries list              |
| 23 13 01 00       | 23 03 04 00 02 45 55  | frequency table entry                     |
| 23 13 01 xx       | 23 03 xx yy zz        | frequency table entry                     |
4. close and reopen with 230400 Baud
| send              | receive               | comment                                   |
| -----             | ---------             | ---------                                 |
| 23 05 00 49 47    | 23 05 00              | reset command                             |
| 23 01 00          | 23 01 04 05 00 02 37  | FW version?                               |
| 23 0e 01 01       | 23 0e 00              | ?                                         |
| 23 02 01 00       | 23 02 00              | 00=frequency band out of frequency table  |
| 23 03 00          | 23 03 18 00 00 01...  | frequency table entries list              |
| 23 13 01 00       | 23 03 04 00 02 45 55  | frequency table entry                     |
| 23 13 01 xx       | 23 03 xx yy zz        | frequency table entry                     |
5. Send 23 04 00
6. Packets receiving
7. Stop with 23 05 00

### Minimal sequence with working results for EU frequency
1. open directly with 230400 baud
2. sequence
| send              | receive               | comment                                   |
| -----             | ---------             | ---------                                 |
| 23 05 00 49 47    | 23 05 00              | reset command                             |
| 23 01 00          | 23 01 04 05 00 02 37  | FW version?                               |
| 23 0e 01 01       | 23 0e 00              | ?                                         |
| 23 02 01 00       | 23 02 00              | 00=frequency band out of frequency table  |
| 23 03 00          | 23 03 18 00 00 01...  | frequency table entries list              |
3. Send 23 04 00
4. Packets receiving
5. Stop with 23 05 00

### Commands
1. 23 05 00 49 47 -> init
2. 23 01 00 -> get info
3. 23 02 01 xx -> set country (xx=table id)
4. 23 03 00 -> get country tables; returns (23 03 <length> 00 <tables>)
5. 23 13 01 xx -> query country table; returns (23 13 <length> xx <02/03?> <regioncode>)
6. 23 04 00 -> start sniffing
7. 23 05 00 -> stop sniffing

### sniffing packets

WakeUp Start:
21 04 aa bb cc dd ee <data>
ee - RSSI
<data>[N] N=3 or N=4 depends on data: uu vv ww xx : N=4 if ww > 0
     uu = WakeBeam always 0x55
     xx = HomeID Hash

WakeUp Stop
21 05 aa bb cc <data>
cc - RSSI
<data>[2]- Observations show always two byte "counter"

Normal Frames:

21 01 aa bb cc dd ee ff gg hh <frame>

ee - RSSI
ff - 21
gg - 03
hh - length of frame

cc dd?
21 00 - 40kbit ch1
02 00 - 100 Kbit ch0
20 00 - 9k6 Ch 1
