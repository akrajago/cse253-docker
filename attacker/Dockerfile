FROM ubuntu:22.04
RUN apt update
RUN apt install -y python3 python3-pip iproute2
RUN pip3 install scapy
COPY spoof_tcp.py ./spoof_tcp.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
