![alt tag](https://raw.github.com/achinkulshrestha/CrimeCheck/master/crimecheck.png)
==========

Compression Ratio Info-leak Made Easy (CRIME) is a security exploit published in 2012 against TLS Compression. When used to recover the content of secret authentication cookies, over connections using the HTTPS and SPDY protocols that also use data compression, it allows an attacker to perform session hijacking on an authenticated web session. 

The Effects of CRIME attacks against TLS compression were demonstrated and largely mitigated in browsers and servers. The CRIME exploit against HTTP compression, however has not been mitigated and then Breach came into existence

The BREACH attack is an instance of the CRIME attack against HTTP compression - the use by many web browser and web servers of gzip or DEFLATE data compression algorithms via the content-encoding option within HTTP

CRIME CHECK is a tool to detect if the server has TLS or HTTP Compression Enabled and thus vulnerable to these attacks. 

BASIC USAGE:
==========
CrimeCheck - A Tool to check if the server is vulnerable to Compression Based Attacks(BREACH/CRIME)
usage: PROGRAM [options] <...>
  -v  Verbose logging
  -l log_file Log output to logfile
  -s  Server URL
  -p  Pcap File (Live Capture is not supported currently) 
Copyright (C) 2013 Achin K, mail: achinkul@gmail.com

CHECKING HTTP COMPRESSION (BREACH/CRIME ATTACK)
==========
crimecheck.py -s <SERVER-DOMAIN>

CHECKING TLS COMPRESSION (CRIME ATTACK)
==========
crimecheck.py -s <SERVER-DOMAIN> -p <PCAP-FILE>

VERBOSE
==========
crimecheck.py -v -s <SERVER-DOMAIN> -p <PCAP-FILE>

EXAMPLE
==========
crimecheck.py -v -s facebook.com -p sample.pcap

NOTE: The Tool doesn't support live capture, for that purpose please use pypcap(https://code.google.com/p/pypcap/). The Tool is compatible with Python 2.7





  
                                                                                                           
