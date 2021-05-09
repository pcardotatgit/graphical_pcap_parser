import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.compat import compat_ord
import struct
import socket
import csv
import datetime
import sqlite3
import sys
import os

def main():
    print('File to parse = /files/f.pcap')
    file=os.path.join("./files/", "f.pcap")
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)
    #c = csv.writer(open("resultat.csv", "w"))
    data=[]
    i=0
    print('Parsing Data... ')
    for timestamp, buf in pcap:
        time=str(datetime.datetime.utcfromtimestamp(timestamp))
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        do_not_fragment = bool(dpkt.ip.IP_DF)
        more_fragments = bool(dpkt.ip.IP_MF)
        fragment_offset = bool(dpkt.ip.IP_OFFMASK)
        Source = "%s" % ip_to_str(ip.src)
        Destination = "%s" % ip_to_str(ip.dst)
        length = "%d" % (ip.len)
        TTL = "%d" % (ip.ttl)
        OFF = ip.off
        TOS = ip.tos
        Protocol = ip.p        
        donnee = ip.data
        mac_source=mac_addr(eth.src)
        mac_destination=mac_addr(eth.dst)
        port_source=0
        port_destination=0
        str_proto=str(Protocol)
        Protocole = protocols[str_proto]
        if Protocol==6:
            port_source=ip.tcp.sport
            port_destination=ip.tcp.dport
        elif Protocol==17:
            port_source=ip.udp.sport
            port_destination=ip.udp.dport
        '''            
        if ( port_destination == 80 or port_destination == 443 ) and len(donnee) > 0:
            http = dpkt.http.Request(donnee)
            #print (http.uri)
            #print (http.method)
            #print (http.version)
            #print (http.headers['user-agent'])
            method=http.method
        '''    
        info='not used'
        #method="test"
        data.append ((i,time,Source,mac_source, Destination,mac_destination, Protocole,port_source,port_destination,length,info))
        #print (Destination)
        i=i+1
    print('DONE')    
    print('Adding resulting Data to SQLI database')
    cursor=data_to_db(data)
        
if __name__ == '__main__':
    main()
    # call python parse_pcap.py trace.pcap