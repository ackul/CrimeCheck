#!/usr/bin/env python
"""
CrimeCheck - A Tool to check if the server is vulnerable to the Crime/Breach Attack
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
import dpkt

DEBUG = False
capture=""
def sendRequest(serverAddr):
    req = urllib2.Request(serverAddr)
    req.add_header('Accept-Encoding', 'gzip,deflate')
    resp = urllib2.urlopen(req)
    content = resp.read()
    return resp.info().getheader('Content-Encoding')

def checkIfVulnerable(respCode,serverAddr):
    if respCode:
        logger.info("Server %s supports HTTP Compression",serverAddr)
    else:
        logger.info("Server %s doesn't support HTTP Compression",serverAddr)
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

def gather_statistics(cap):
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

        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        if ord(tcp.data[0]) != TLS_HANDSHAKE:
            continue

        if DEBUG:
            print 'tcp.sport: %d' % (tcp.sport)
            print 'tcp.dport: %d' % (tcp.dport)
            print 'tcp.data[0]: %d' % ord(tcp.data[0])
            print 'tcp.sum: 0x%x' % tcp.sum

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
            if ord(record.data[0]) != 1:
                continue

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData, e:
                # TODO: shouldn't happen in practice for handshakes... but could. meh.
                continue

            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                continue

            counters['client_hellos_total'] += 1

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

            if DEBUG:
                print ""
                print 'ch.session_id.version: %s' % dpkt.ssl.ssl3_versions_str[ch.version]
                print 'ch.session_id.len: %d' % len(ch.session_id)
                print 'ch.num_ciphersuites: %d' % ch.num_ciphersuites
                print 'ch.num_compression_methods: %d' % ch.num_compression_methods
                print 'ch.compression_methods: %s' % str(ch.compression_methods)

            if 1 in ch.compression_methods:
                counters['deflate_support'] += 1

            counters['extension_count_%d' % (len(ch.extensions))] += 1
            count_extensions.add(len(ch.extensions))

            if DEBUG:
                import binascii
                for ext in ch.extensions:
                    print 'extType: (%d) %s' % (ext.value, ext.name)
                    print 'extData: %s' % (binascii.hexlify(ext.data))
            for ext in ch.extensions:
                known_extensions.add(ext.name)
                counters['ext_%s' % (ext.name)] += 1
    stats = [
        {
            'name': 'Client Hello seen',
            'value': str(counters['client_hellos_total']),
        },
        {
            'name': 'SSL v3 Clients',
            'value': as_percent(counters['SSLv3_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1 Clients',
            'value': as_percent(counters['TLSv1_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1.1 Clients',
            'value': as_percent(counters['TLSv1.1_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1.2 Clients',
            'value': as_percent(counters['TLSv1.2_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'Sent SessionID',
            'value': as_percent(counters['session_id_sent'], counters['client_hellos_total']),
        },
        {
            'name': 'Deflate Support',
            'value': as_percent(counters['deflate_support'], counters['client_hellos_total']),
        }
        ]

    for ext in sorted(known_extensions):
        stats.append({
            'name': 'Support for %s extension' % ext,
            'value': as_percent(counters['ext_%s' % ext], counters['client_hellos_total']),
        })
    for count in sorted(count_extensions):
        stats.append({
            'name': 'Sent %d extension' % count,
            'value': as_percent(counters['extension_count_%s' % count], counters['client_hellos_total']),
        })
    return stats

        

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
        if o in ("-s", "--server-url"):serverAddr = str(a)
        if o in ("-p", "--pcap-file"):
            with open(a, 'rb') as fp:
                capture = pcap_reader(fp)
                stats = gather_statistics(capture)
          
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if (fileHandler is not None):
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
    serverAddr="https://google.com"
    logger.info("Ready. Sending Request... ")
    if serverAddr == "":
        die_usage("Please Enter Server Address")
    try:
       respCode = sendRequest(serverAddr)
       checkIfVulnerable(respCode,serverAddr)
       if capture:
           stats = gather_statistics(capture)
       else:
           logger.info("To check for TLS Compression, Please provide a PCAP file")
    except:
        logger.info("Error...Booting out")
    





