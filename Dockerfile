FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
    bridge-utils \
    net-tools \
    iptables \
    python \
    tcpdump \
    build-essential \
    python-dev \
    libnetfilter-queue-dev \
    python-pip

RUN pip install scapy
RUN pip install NetfilterQueue

ADD ./nfqueue_listener.py /nfqueue_listener.py

ENV QUEUE_NUM=1

ENTRYPOINT python nfqueue_listener.py
