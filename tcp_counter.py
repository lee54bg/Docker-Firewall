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
counter = 0

def close_connection(socket, nfq):
    socket.close()
    nfq.unbind()
    
def tcp_counter(pkt):
    packet = IP(pkt.get_payload())
    global counter
    
    if packet.haslayer(TCP):
        counter += 1
        print("TCP Packet #{}".format(counter))
    
    pkt.accept()

try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 0))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)

sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, tcp_counter)

s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    sys.stdout.write('Exiting \n')
    close_connection(s, nfqueue)
    sys.exit(1)

close_connection(s, nfqueue)
sys.exit(1)

if __name__ == '__main__':
    Firewall()
