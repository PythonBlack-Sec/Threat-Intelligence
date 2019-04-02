#!/usr/bin/python
from scapy.all import *
from scapy.all import IP, sniff
from scapy.layers import http
import requests,time,json,Queue #FIFO queue, 4/min
import urllib # trying for report/threatquesry
import sys

"""
SRT311 Course Project

Author: Jorin Grant

Objective:
In this project, I will leverage a powerful python library for packet manipulation and inspection,
called Scapy. In this project, I will create a packet sniffer that inspects traffic on a local area
network and extracts outbound IP connections and HTTP requests. These indicators (IP and hostnames)
are then queried to a threat intelligence (TI) service provider named Virus Total, to identify their maliciousness.

My API key:e1b135d36f93075b5660a380a755999eebe8435fd616503cc46a468478f17cac
"""



global key
key = "e1b135d36f93075b5660a380a755999eebe8435fd616503cc46a468478f17cac"
host_ip = "10.0.2.15"


def threat_report_pcap(file):
    a = rdpcap(file)
    ip_a = []
    sessions = a.sessions()
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                    pcap_ip = packet[IP].dst
                    if not pcap_ip == host_ip:
                        ip_a.append(pcap_ip)
            except:
                pass
    ip_u = set(ip_a)
    #print ip_u # DEBUG LINE -- got unique IPs from pcap file
    for ip in ip_u:
        threat_report(ip, True)

    print "\n[*] Finished [*]"
    print "Report saved to: Malicious-IPs.txt"

def threat_report(host, mode):
#    params = {"apikey" : "e1b135d36f93075b5660a380a755999eebe8435fd616503cc46a468478f17cac", "ip": host}
    params = {"apikey": key, "ip": host}
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(params))).read()
    try:
        response_dict = json.loads(response)
        try:
            for k,v in response_dict.items(): # Look for response and if so, if there are + thenits malicious
                if k == "detected_urls" and v[0]["positives"] > 0:
                    print "Malicious IP found: {}".format(host)
                    # add IP to file!!!! new function??
                    if mode == True: ########### TESTING WRITE IF MANUAL TRUE
                        with open("Malicious-IPs.txt","a") as textfile:
                            textfile.write("{}\n".format(host))
        except:
            pass
            #print "Nothing found"
            #return
    except ValueError:
        print "Limit reached. Waiting..."
        time.sleep(60)
        pass

def process_tcp_packet(packet):
    """
    Process a TCP packet, and if it contains an HTTP request, print it.
    """
    if not packet.haslayer(http.HTTPRequest):
    # Packet has nothing, skip it.
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer   = packet.getlayer(IP)
    #print '\n{0[dst]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
    #print ip_layer.fields # Find dest IP
    field = ip_layer.fields
    for dest, ip in field.items():
        if dest == "dst":
            host_ip = ip
            #print "sniffing interface"
            #print host_ip # DEBUG LINE
    threat_report(host_ip, False)

# Start sniffing
#sniff(filter='tcp',prn=process_tcp_packet)
#threat_report("173.194.197.157", True)

def main():
    if not len(sys.argv[1:]):
        sniff(filter='tcp',prn=process_tcp_packet)
    else:
        pcap = sys.argv[1]
        threat_report_pcap(pcap)

main()
