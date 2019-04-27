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

ADD ./tcp_counter.py /tcp_counter.py

ENV QUEUE_NUM=0

ENTRYPOINT python tcp_counter.py
