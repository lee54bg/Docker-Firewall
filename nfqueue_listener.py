#! /usr/bin/env python2.7

from scapy.all import *
from netfilterqueue import NetfilterQueue
from pprint import pprint
import socket
import os
import sys
import threading
from threading import Thread

access_control = []
rule = dict()

class Firewall(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def close_connection(socket, nfq):
        socket.close()
        nfq.unbind()
    
    def run(self):
        try:
            QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
        except ValueError as e:
            sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
            sys.exit(1)

        sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))

        nfqueue = NetfilterQueue()
        nfqueue.bind(QUEUE_NUM, self.callback)

        s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            nfqueue.run_socket(s)
        except KeyboardInterrupt:
            sys.stdout.write('Exiting \n')
            close_connection(s, nfqueue)
            sys.exit(1)

        close_connection(s, nfqueue)
        sys.exit(1)

    def callback(self, pkt):
        try:
            # <type 'netfilterqueue.Packet'>
            # print(type(pkt))
            
            packet = IP(pkt.get_payload())

            # <class 'scapy.layers.inet.IP'>
            # print(type(packet))
            
            if packet.haslayer(TCP):
                if 'src_port' in rule:
                    if packet[TCP].sport == rule['src_port']
                if 'dst_port' in rule:
                    if packet[TCP].dport == rule['dst_port']
            if packet.haslayer(UDP):
                if 'src_port' in rule:
                    if packet[UDP].sport == rule['src_port']
                if 'dst_port' in rule:
                    if packet[UDP].dport == rule['dst_port']

            if packet.haslayer(IP):
                if 'src_ip' in rule:
                    if packet[IP].src == rule['src_ip']
                if 'dst_ip' in rule:
                    if packet[IP].dst == rule['dst_ip']
        except Exception as e:
            print 'Error: %s' % str(e)
            pkt.drop()
    
def basic_function():
    try:
        while True:
            intro = "\nWelcome to CMPE 210\n\n" \
            "Please specify the following modes\n" \
            "1) Manual Mode\n" \
            "2) Upload Mode\n" \
            "3) Exit\n\n"

            mode = raw_input(intro)

            if(mode == "1"):
                src_ip = raw_input("Enter the Source IP Address: ")
                dst_ip = raw_input("Enter the Destination IP Address: ")
                src_port = raw_input("Enter the Source Port: ")
                dst_port = raw_input("Enter the Destination Port: ")
                action = raw_input("Accept or Block: ")

                set_params(src_ip, dst_ip, src_port, dst_port, action)
                print("Entry successfully added\n")

            elif(mode == "2"):
                print("Upload mode\n")
            elif(mode == "3"):
                print("Exiting the Firewall...\n")
                sys.exit(1)
            else:
                print("Please try again\n")
    except KeyboardInterrupt:
        print("Exiting basic function")
        sys.exit(1)

def set_params(src_ip, dst_ip, src_port, dst_port, action):
    if src_ip != "":
        rule.update({"src_ip": src_ip})
    if dst_ip != "":
        rule.update({"dst_ip": dst_ip})
    if src_port != "":
        rule.update({"src_port": src_port})
    if dst_port != "":
        rule.update({"dst_port": dst_port})
    if action != "":
        rule.update({"action": action})
    
    print(rule)

def packet_actions(packet):
    packet.accept()

# def valid_ip():

# def valid_port():

def valid_action(action):
    if action == "accept":
        rule.update({"action": action})
    if action == "block":
        rule.update({"action": action})
    else:
        print("Invalid Action.  Please try again.\n")
        continue


Firewall()

t1 = threading.Thread(target=basic_function)
t1.start()