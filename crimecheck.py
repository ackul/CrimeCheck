#!/usr/bin/env python
"""
CrimeCheck - A Tool to check if the server is vulnerable to Compression Based Attacks(BREACH/CRIME)
usage: PROGRAM [options] <...>
  -v  Verbose logging
  -l log_file Log output to logfile
  -s  Server URL
  -p  Pcap File (Live Capture is not supported currently) 
Copyright (C) 2013 Achin K, mail: achinkul@gmail.com
Thanks to Paul Querna for the amazing parser 
"""
import urllib2
import logging, getopt
import os
import sys
import socket

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'third_party', 'dpkt')
if p not in sys.path:    
    sys.path.insert(0, p)

import dpkt
from collections import defaultdict


capture=""

def sendRequest(serverAddr):
    req = urllib2.Request("https://"+serverAddr)
    req.add_header('Accept-Encoding', 'gzip,deflate')
    resp = urllib2.urlopen(req)
    content = resp.read()
    return resp.info().getheader('Content-Encoding')

def checkIfVulnerable(respCode,serverAddr):
    if respCode:
        logger.info("HTTP Compression for Server %s is ENABLED ",serverAddr)
    else:
        logger.info("HTTP Compression for Server %s is DISABLED",serverAddr)
def pcap_reader(fp):
    return dpkt.pcap.Reader(fp)

def as_percent(a, b):
    if a == 0:
        return "0%"
    if a > b:
        assert('invalid percentage')

    val = float(a) / float(b)
    return "%.2f%%" % (val * 100)

TLS_HANDSHAKE = 22

def gather_statistics(cap,serverAddr):
    counters = defaultdict(int)
    known_extensions = set()
    count_extensions = set()
    pkt_count = 0
    for ts, buf in cap:
        pkt_count += 1
        eth = dpkt.ethernet.Ethernet(buf)
        #print 'pkt: %d' % (pkt_count)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # TODO: consider doing TCP streams, so multi-packet things can be parsed right... "meh"
        tcp = ip.data
        if tcp.dport != 443 and tcp.sport != 443:
            continue
        if socket.gethostbyname(serverAddr) != socket.inet_ntoa(ip.src):
            continue
        
        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        if ord(tcp.data[0]) != TLS_HANDSHAKE:
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.TLSMultiFactory(tcp.data)
        except dpkt.ssl.SSL3Exception, e:
            # TODO: debug these
            continue
        except dpkt.dpkt.NeedData, e:
            # TODO: meeeeh
            continue

        if len(records) <= 0:
            continue

        for record in records:
            # TLS handshake only
            if record.type != 22:
                continue
            if len(record.data) == 0:
                continue
            # Client Hello only
            if ord(record.data[0]) != 2:
                continue
            counters['Handshake_hellos_total'] += 1
            if counters['Handshake_hellos_total'] == 1:
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                except dpkt.dpkt.NeedData, e:
                    # TODO: shouldn't happen in practice for handshakes... but could. meh.
                    continue         
            

                ch = handshake.data

                if ch.version == dpkt.ssl.SSL3_V:
                    counters['SSLv3_clients'] += 1
                elif ch.version == dpkt.ssl.TLS1_V:
                    counters['TLSv1_clients'] += 1
                elif ch.version == dpkt.ssl.TLS11_V:
                    counters['TLSv1.1_clients'] += 1
                elif ch.version == dpkt.ssl.TLS12_V:
                    counters['TLSv1.2_clients'] += 1

                if len(ch.session_id) > 0:
                    counters['session_id_sent'] += 1
                if ch.compression != 0:
                    counters['TLSCompression'] += 1

            
                if counters['TLSCompression'] > 0:
                    logger.info("The TLS Compression for server %s is ENABLED", serverAddr)
                    break
                else:
                    logger.info("The TLS Compression for server %s is DISABLED", serverAddr)
                    break
    if counters['Handshake_hellos_total'] == 0:
        logger.info("The PCAP file doesn't contain any SSL Handshake Packets corresponding to %s ", serverAddr)              
 
if __name__ == '__main__':

    __usage__ = __doc__.replace("PROGRAM", os.path.basename(sys.argv[0]))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fileHandler = None
    serverAddr = ""
    
    def die_usage(msg=""):
        sys.stderr.write("%s%s\n" % (__usage__, msg))
        sys.exit(1)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvl:s:p:", ["help", "verbose", "log-file", "server-url"])
    except getopt.GetoptError, e:        
        die_usage(str(e))
    for o, a in opts:
        if o in ("-h","--help"): die_usage()
        if o in ("-v", "--verbose"): logger.setLevel(logging.DEBUG)                
        if o in ("-l", "--log-file"): fileHandler = logging.FileHandler(a)
        if o in ("-s", "--server-url"):
            serverAddr = str(a)
            pcap = None
        if o in ("-p", "--pcap-file"):
            if a:
                pcap = str(a)
            else:
                logger.info("Please enter a valid pcap file")
                
          
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if (fileHandler is not None):
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)    
    
    if serverAddr == "":
        die_usage("\nPlease Enter Server Address")
    try:      
        logger.info("Ready. Sending Request to server %s", serverAddr)
        respCode = sendRequest(serverAddr)
        checkIfVulnerable(respCode,serverAddr)
        logger.info("Checking TLS Compression for %s", serverAddr)
        if pcap:
            fp = open(pcap,'rb')
            capture = pcap_reader(fp)
            stats = gather_statistics(capture, serverAddr)
        else:
            logger.info("To check for TLS Compression, Please provide a PCAP file")
    except Exception as e :
        logger.info("Error - %s",e)
    





