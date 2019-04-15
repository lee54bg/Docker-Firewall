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

            match = None
            rule_match = None

            for item in access_control:
                if 'src_port' in rule:
                    print("src_port")

                    if packet.haslayer(TCP):
                        if packet[TCP].sport == rule['src_port']:
                            match = True
                        else:
                            match = False
                    elif packet.haslayer(UDP):
                        if packet[UDP].sport == rule['src_port']:
                            match = True
                        else:
                            match = False
                if 'dst_port' in rule:
                    if packet.haslayer(TCP):
                        if packet[TCP].dport == rule['dst_port']:
                            match = True
                        else:
                            match = False
                    elif packet.haslayer(UDP):
                        if packet[UDP].sport == rule['dst_port']:
                            match = True
                        else:
                            match = False

                if 'src_ip' in rule:
                    if packet.haslayer(IP):
                        if packet[IP].src == rule['src_ip']:
                            match = True
                        else:
                            match = False
                if 'dst_ip' in rule:
                    if packet.haslayer(IP):
                        if packet[IP].dst == rule['dst_ip']:
                            match = True
                        else:
                            match = False

                if match is True:
                    rule_match = item
            
            print match
            print rule_match
            if match is True:
                if rule_match['action'] == "accept":

                    pkt.accept()
                    print("accpeted packet")
                if rule_match['action'] == "block":
                    pkt.drop()
            elif match is False:
                pkt.accept()
            
                # if 'src_port' in rule:
                #     print("TCP src_port")

            #         if packet[TCP].sport == rule['src_port']:
            #             print packet[TCP].sport
            #     if 'dst_port' in rule:
            #         print("TCP dst_port")

            #         if packet[TCP].dport == rule['dst_port']:
            #             print packet[TCP].dport
            # if packet.haslayer(UDP):
            #     if 'src_port' in rule:
            #         print("UDP src_port")

            #         if packet[UDP].sport == rule['src_port']:
            #             print packet[UDP].sport
            #     if 'dst_port' in rule:
            #         print("UDP dst_port")

            #         if packet[UDP].dport == rule['dst_port']:
            #             print packet[UDP].sport
            # if packet.haslayer(IP):
            #     if 'src_ip' in rule:
            #         if packet[IP].src == rule['src_ip']:
            #             print packet[IP].src
            #     if 'dst_ip' in rule:
            #         if packet[IP].dst == rule['dst_ip']:
            #             print packet[IP].dst
        except Exception as e:
            print 'Error: %s' % str(e)
            pkt.drop()

def basic_function():
    try:
        while True:
            intro = "\nWelcome to CMPE 210\n\n" \
            "Please specify the following options\n" \
            "1) Insert Rule\n" \
            "2) Exit\n\n"

            mode = raw_input(intro)

            if(mode == "1"):
                src_ip = raw_input("Enter the Source IP Address: ")
                dst_ip = raw_input("Enter the Destination IP Address: ")
                src_port = raw_input("Enter the Source Port: ")
                dst_port = raw_input("Enter the Destination Port: ")
                action = raw_input("Accept or Block: ")

                set_params(src_ip, dst_ip, src_port, dst_port, action)
                
                access_control.append(rule)
                print("Entry successfully added\n")
            elif(mode == "2"):
                print("Exiting the Firewall...\n")
                sys.exit(1)
            else:
                print("Please try again\n\n")
    except KeyboardInterrupt:
        print("Exiting basic function")
        sys.exit(1)

def set_params(src_ip, dst_ip, src_port, dst_port, action):
    if src_ip != "":
        rule.update({"src_ip": src_ip})
    if dst_ip != "":
        rule.update({"dst_ip": dst_ip})
    if src_port != "":
        rule.update({"src_port": int(src_port)})
    if dst_port != "":
        rule.update({"dst_port": int(dst_port)})
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
        return True
    elif action == "block":
        rule.update({"action": action})
        return True
    else:
        return False

Firewall()

t1 = threading.Thread(target=basic_function)
t1.start()
