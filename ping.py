#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 26 17:53:39 2023

@author: zach
"""
from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 20
TIMEOUT = 3.0
TRIES = 2

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myChecksum = 0
    header = struct.pack("bbHh", ICMP_ECHO_REQUEST, 0, myChecksum, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(str(header + data))
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, (os.getpid() & 0xFFFF), 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    for ttl in range(1, MAX_HOPS):
        print("\nTTL =", ttl)
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    print(" * * * Request timed out.")
                else:
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeReceived = time.time()
                    
                    # Fetch the ICMP type from the IP packet
                    icmpHeader = recvPacket[20:28]
                    types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                    if types == 11:
                        # Extract the IP header from the received packet
                        ipHeader = recvPacket[0:20]
                        iph = struct.unpack('!BBHHHBBH4s4s', ipHeader)

                        # Extract the source IP address from the IP header
                        sourceIP = inet_ntoa(iph[8])
                        print("  %d\t%s" % (ttl, sourceIP))
                        break
                    elif types == 3:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print(" %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0]))
                    elif types == 0:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print(" %d rtt=%.0f ms %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0]))
                        return
                    else:
                        print("error")
            except timeout:
                print(" * * * Request timed out.")
            finally:
                mySocket.close()

def traceroute_to_hosts(hosts):
    for host in hosts:
        print("\nTracing route to", host)
        get_route(host)




# Call the new function with a list of three target hosts
traceroute_to_hosts(["google.com", "yahoo.com", "bing.com"])