# Description
The setup consists of 4 containers:
- Phone (10.0.0.193)
- Destination (10.0.0.187)
- Middlebox (10.0.0.230)
- Attacker (10.0.0.111)

The attacker spoofs a TCP connection between the phone and destination using TTL-limited TCP packets which only reach the middlebox.

## Usage
Make sure the Docker Desktop daemon is running on your computer. Then run docker compose in attached (foreground) mode:
```shell
docker compose up --build
```
or detached (background) mode:
```shell
docker compose up --build -d
```
to bring up the containers.

Next, enter the middlebox and attacker containers with the following commands:
```shell
docker exec -it <middlebox_container_name> /bin/bash
docker exec -it <attacker_container_name> /bin/bash
```

In the middlebox container, run `tcpdump`:
```shell
tcpdump -ni eth0 host 10.0.0.193 or host 10.0.0.187
```

To generate a pcap file, run:
```shell
tcpdump -ni eth0 host 10.0.0.193 or host 10.0.0.187 -w <pcap_name>
```

In the attacker container, run the spoofing script:
```shell
python3 spoof_tcp.py
```

To export a pcap file to your local machine, run:
```shell
docker cp <middlebox_container_name>:<path_to_pcap_in_container> <local_machine_destination>
```
in your local shell.

## Cleanup
To stop `tcpdump`, enter `ctrl+C`. To exit the containers, enter `ctrl+D`.

To stop running docker compose in attached mode, enter `ctrl+C`. To stop in detached more, run:
```shell
docker compose down
```
