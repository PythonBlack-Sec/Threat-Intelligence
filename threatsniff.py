#!/usr/bin/env python
from scapy.all import *
from scapy.all import IP, sniff
from scapy.layers import http
import requests,time,json,Queue #FIFO queue, 4/min
import urllib 
import sys
import os

"""
Author: PythonBlack

Objective:
In this project, I will leverage a powerful python library for packet manipulation and inspection,
called Scapy. In this project, I will create a packet sniffer that inspects traffic on a local area
network and extracts outbound IP connections and HTTP requests. These indicators (IP and hostnames)
are then queried to a threat intelligence (TI) service provider named Virus Total, to identify their maliciousness.
"""



global key
key = "" # Enter VirusTotal API key
host_ip = "10.0.2.15"


def threat_report_pcap(file): # For reading from PCAP files
    a = rdpcap(file) # Read specified PCAP
    ip_a = [] # List of all IPs from PCAP
    sessions = a.sessions()
    for session in sessions:
        for packet in sessions[session]: # Look for HTTP/S traffic in each packet from all sessions in PCAP
            try:
                if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                    pcap_ip = packet[IP].dst
                    if not pcap_ip == host_ip: # Do not query host IP then append found IP to list of all IPs
                        ip_a.append(pcap_ip)
            except:
                pass
    ip_u = set(ip_a) # Make new lsit of IPs that are unique to save space
    #print ip_u # DEBUG LINE -- got unique IPs from pcap file
    for ip in ip_u:
        threat_report(ip, True) # Query VirusTotal for each unique IP. True mode enables malicous host IPs to be written to a file

    print "\n[*] Finished [*]"
    if os.path.isfile("Malicious-IPs.txt"):
        print "\033[91mReport saved to: Malicious-IPs.txt\033[0m"
    else:
        print "\033[92mNo malicious IPs found\033[0m"

def threat_report(host, mode):
    params = {"apikey": key, "ip": host}
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(params))).read() # Send query to VT and save resposne to a variable "response"
    try:
        response_dict = json.loads(response)
        try:
            for k,v in response_dict.items(): # Parse response for positive results then display IP or add it to a file
                if k == "detected_urls" and v[0]["positives"] > 5: # increase "5" to tune for false positives
                    # OG print "Malicious IP found: {}".format(host)
                    print "Malicious IP found: {} ".format(host) + "| Positive results:" + v[0]["positives"]
                    if mode == True:
                        with open("Malicious-IPs.txt","a") as textfile:
                            textfile.write("{}\n".format(host))
        except:
            pass
    except ValueError: # Free API key has a limit of 4 queries per minute - catch error and wait
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
    print '\n{0[dst]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields) # DEBUG
    #print ip_layer.fields # Find dest IP # DEBUG
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
    uid = os.getuid()
    if uid !=0: # Ensure script has root permissions
         print "\033[93mScript must be run with sudo privileges!\033[0m"
    else: # Script has root
        if not len(sys.argv[1:]): # live monitor interface
            sniff(filter='tcp',prn=process_tcp_packet)
        else: # read PCAP file
            pcap = sys.argv[1]
            threat_report_pcap(pcap)

main()
