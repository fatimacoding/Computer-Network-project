import threading
import time
import signal
import sys
import socket
import os
from scapy.all import sniff
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.config import conf
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd


# Dictionaries and sets to store metrics
protocol_bytes = defaultdict(int)
connection_timestamps = {}
latency_values = defaultdict(list)
protocol_packet_counts = defaultdict(int)
protocol_packet_counts['TCP_Connections'] = 0
protocol_packet_counts['UDP_Connections'] = 0
protocol_packet_counts['Ethernet_Connections'] = 0
packet_sizes = defaultdict(list)
unique_ips = set()
unique_macs = set()
total_connections = 0
connection_rates = []
lock = threading.Lock()

# Throughput over time data for visualization
throughput_data = defaultdict(list)
throughput_timestamps = []

# Timeout for latency measurements (in seconds)
LATENCY_TIMEOUT = 10

# Global variable to control sniffing
stop_sniffing = False

# Open the log file
log_file = open('network_events.log', 'a')

# Server setup for multi-connection management
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 9999))
server.listen(5)

def handle_client_connection(client_socket):
    global total_connections
    with lock:
        total_connections += 1
    client_socket.close()

def accept_connections():
    global stop_sniffing
    while not stop_sniffing:
        try:
            client_sock, address = server.accept()
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock,)
            )
            client_handler.daemon = True
            client_handler.start()
        except OSError:
            # Socket has been closed, exit the loop
            break

def calculate_throughput():
    interval = 10  # Time interval in seconds
    while not stop_sniffing:
        time.sleep(interval)
        with lock:
            timestamp = time.time()
            throughput_timestamps.append(timestamp)
            for protocol in protocol_bytes:
                if protocol != 'ARP':
                    throughput = (protocol_bytes[protocol] * 8) / interval  # bps
                    print(f"Throughput for {protocol}: {throughput} bps")
                    throughput_data[protocol].append((timestamp, throughput))
                    protocol_bytes[protocol] = 0  # Reset the counter

def packet_handler(packet):
    global total_connections
    with lock:
        timestamp = time.time()
        protocol = 'Other'
        size = len(packet)
        src_mac = dst_mac = src_ip = dst_ip = src_port = dst_port = ''
        tcp_flags = ''

        # Validate and extract Ethernet layer
        if Ether in packet:
            ether_layer = packet[Ether]
            src_mac = ether_layer.src
            dst_mac = ether_layer.dst
            unique_macs.update([src_mac, dst_mac])
            protocol_packet_counts['Ethernet'] += 1
            packet_sizes.setdefault('Ethernet', []).append(size)
            protocol_bytes['Ethernet'] += size
            protocol_packet_counts['Ethernet_Connections'] += 1

        # Validate and extract ARP layer
        if ARP in packet:
            arp_layer = packet[ARP]
            protocol = 'ARP'
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            unique_ips.update([src_ip, dst_ip])
            protocol_packet_counts['ARP'] += 1
            packet_sizes.setdefault('ARP', []).append(size)
            protocol_bytes['ARP'] += size

        # Validate and extract IP layer
        elif IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            unique_ips.update([src_ip, dst_ip])
            protocol_packet_counts['IP'] += 1
            packet_sizes.setdefault('IP', []).append(size)
            protocol_bytes['IP'] += size

            # Check for TCP/UDP layers
            if TCP in packet:
                tcp_layer = packet[TCP]
                protocol = 'TCP'
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = tcp_layer.flags
                protocol_packet_counts['TCP'] += 1
                packet_sizes.setdefault('TCP', []).append(size)
                protocol_bytes['TCP'] += size
                protocol_packet_counts['TCP_Connections'] += 1

                # Increment total_connections for new TCP connections
                conn_id = (src_ip, src_port, dst_ip, dst_port, protocol)
                if conn_id not in connection_timestamps:
                    total_connections += 1  # Increment total connections
                    connection_timestamps[conn_id] = timestamp  

            elif UDP in packet:
                udp_layer = packet[UDP]
                protocol = 'UDP'
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol_packet_counts['UDP'] += 1
                packet_sizes.setdefault('UDP', []).append(size)
                protocol_bytes['UDP'] += size
                protocol_packet_counts['UDP_Connections'] += 1

                # Increment total_connections for new UDP connections
                conn_id = (src_ip, src_port, dst_ip, dst_port, protocol)
                if conn_id not in connection_timestamps:
                    total_connections += 1  # Increment total connections
                    connection_timestamps[conn_id] = timestamp  

            else:
                protocol = 'IP'

        else:
            # Non-IP and non-ARP packets
            protocol_packet_counts['Other'] += 1
            packet_sizes.setdefault('Other', []).append(size)
            protocol_bytes['Other'] += size

        # Logging
        log_entry = f"{timestamp}, {protocol}, {src_mac}, {dst_mac}, {src_ip}, {dst_ip}, {src_port}, {dst_port}, {size}\n"
        log_file.write(log_entry)
        log_file.flush()

        # Latency calculation for TCP/UDP
        if protocol in ['TCP', 'UDP'] and src_ip and dst_ip and src_port and dst_port:
            conn_id_request = (src_ip, src_port, dst_ip, dst_port, protocol)
            conn_id_response = (dst_ip, dst_port, src_ip, src_port, protocol)
            current_time = timestamp

            # Remove outdated timestamps
            for conn_id in list(connection_timestamps.keys()):
                req_time = connection_timestamps[conn_id]
                if current_time - req_time > LATENCY_TIMEOUT:
                    del connection_timestamps[conn_id]

            if conn_id_response in connection_timestamps:
                # Response packet received
                request_time = connection_timestamps.pop(conn_id_response)
                latency = (timestamp - request_time) * 1000  # ms

                if latency > 0:
                    latency_values[protocol].append(latency)
                    print(f"Latency for {protocol} connection {conn_id_response}: {latency:.2f} ms")
            else:
                # Store the timestamp for the request
                connection_timestamps[conn_id_request] = timestamp

def start_sniffing():
    global stop_sniffing
    while not stop_sniffing:
        try:
            sniff(prn=packet_handler, store=False, timeout=1)
        except Exception as e:
            # Handle exceptions that may occur during sniffing
            print(f"Error during sniffing: {e}")
            break

def print_metrics():
    interval = 30  # Time interval in seconds
    while not stop_sniffing:
        time.sleep(interval)
        with lock:
            print("\n--- Real-Time Statistics ---")
            # Number of connections per protocol
            for protocol in latency_values:
                if protocol not in ['ARP', 'Other']:  
                    num_connections = len(latency_values[protocol])
                    print(f"Number of {protocol} connections: {num_connections}")

            # Average packet size per protocol
            for protocol in packet_sizes:
                if protocol not in ['ARP', 'Other'] and packet_sizes[protocol]:
                    avg_size = sum(packet_sizes[protocol]) / len(packet_sizes[protocol])
                    print(f"Average packet size for {protocol}: {avg_size:.2f} bytes")

            # Total packets captured per protocol
            for protocol in protocol_packet_counts:
                if protocol not in ['ARP', 'Other'] and '_Connections' not in protocol:  
                    print(f"Total packets for {protocol}: {protocol_packet_counts[protocol]}")

            # Rate of new connections (connections over time)
            current_time = time.time()
            connection_rates.append((current_time, total_connections))
            print(f"Total connections: {total_connections}")

            # Calculate connection rates
            tcp_rate = protocol_packet_counts['TCP_Connections'] / interval
            udp_rate = protocol_packet_counts['UDP_Connections'] / interval
            ethernet_rate = protocol_packet_counts['Ethernet_Connections'] / interval

            # Display the connection rates
            print(f"Connection rate (TCP): {tcp_rate:.2f} connections/sec")
            print(f"Connection rate (UDP): {udp_rate:.2f} connections/sec")
            print(f"Connection rate (Ethernet): {ethernet_rate:.2f} connections/sec")

            # Reset the connection counters
            protocol_packet_counts['TCP_Connections'] = 0
            protocol_packet_counts['UDP_Connections'] = 0
            protocol_packet_counts['Ethernet_Connections'] = 0

            # Number of unique IP and MAC addresses
            print(f"Unique IP addresses: {len(unique_ips)}")
            print(f"Unique MAC addresses: {len(unique_macs)}")
            print("--- End of Statistics ---\n")

def signal_handler(sig, frame):
    global stop_sniffing
    print('\nGracefully shutting down...')
    stop_sniffing = True  # Signal to stop sniffing
    # Close the server socket
    server.close()
    # Wait for threads to finish
    time.sleep(1)
    # Print final statistics
    print_final_statistics()
    log_file.close()
    sys.exit(0)

def print_final_statistics():
    with lock:
        print("\nFinal Network Statistics:")
        
        # Total number of connections
        print(f"Total connections: {total_connections}")

        # Unique IP and MAC addresses
        print(f"Unique IP addresses: {len(unique_ips)}")
        print(f"Unique MAC addresses: {len(unique_macs)}")

        # Average packet sizes per protocol
        for protocol in packet_sizes:
            if protocol not in ['ARP', 'Other'] and packet_sizes[protocol]:
                avg_size = sum(packet_sizes[protocol]) / len(packet_sizes[protocol])
                print(f"Average packet size for {protocol}: {avg_size:.2f} bytes")

        # Total packets captured per protocol
        for protocol in protocol_packet_counts:
            if protocol not in ['ARP', 'Other'] and '_Connections' not in protocol:  
                print(f"Total packets for {protocol}: {protocol_packet_counts[protocol]}")

        # Number of connections per protocol
        print(f"Number of TCP connections: {protocol_packet_counts['TCP_Connections']}")
        print(f"Number of UDP connections: {protocol_packet_counts['UDP_Connections']}")

        # Calculate and display connection rates
        elapsed_time = time.time() - start_time
        tcp_rate = protocol_packet_counts['TCP_Connections'] / elapsed_time if elapsed_time > 0 else 0
        udp_rate = protocol_packet_counts['UDP_Connections'] / elapsed_time if elapsed_time > 0 else 0
        ethernet_rate = protocol_packet_counts['Ethernet_Connections'] / elapsed_time if elapsed_time > 0 else 0

        print(f"Connection rate (TCP): {tcp_rate:.2f} connections/sec")
        print(f"Connection rate (UDP): {udp_rate:.2f} connections/sec")
        print(f"Connection rate (Ethernet): {ethernet_rate:.2f} connections/sec")

        # Generate the graphs
        generate_graphs()

def generate_graphs():
    # Read log file into a DataFrame
    df = pd.read_csv('network_events.log', names=[
        'Timestamp', 'Protocol', 'Src_MAC', 'Dst_MAC', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Size'
    ])

    # Throughput Over Time
    plt.figure()
    for protocol in throughput_data:
        if protocol not in ['ARP', 'Other'] and throughput_data[protocol]:
            times, throughputs = zip(*throughput_data[protocol])
            plt.plot(times, throughputs, label=protocol)
    plt.xlabel('Time')
    plt.ylabel('Throughput (bps)')
    plt.title('Throughput Over Time')
    plt.legend()
    plt.savefig('throughput_over_time.png')
    plt.show()
    plt.close()

    # Latency Distribution
    plt.figure()
    for protocol in latency_values:
        if protocol not in ['ARP', 'Other'] and latency_values[protocol]:
            plt.hist(latency_values[protocol], bins=50, alpha=0.5, label=protocol)
    plt.xlabel('Latency (ms)')
    plt.ylabel('Frequency')
    plt.title('Latency Distribution')
    plt.legend()
    plt.savefig('latency_distribution.png')
    plt.show()
    plt.close()

    # Protocol Usage
    protocols = ['Ethernet', 'IP', 'TCP', 'UDP']  
    packet_counts = [protocol_packet_counts.get(p, 0) for p in protocols]

    plt.figure()
    plt.bar(protocols, packet_counts)
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Protocol Usage')
    plt.savefig('protocol_usage.png')
    plt.show()
    plt.close()

    # Unique IP and MAC addresses
    address_types = ['Unique IPs', 'Unique MACs']
    address_counts = [len(unique_ips), len(unique_macs)]

    plt.figure()
    plt.bar(address_types, address_counts)
    plt.xlabel('Address Type')
    plt.ylabel('Count')
    plt.title('Unique Address Counts')
    plt.savefig('unique_addresses.png')
    plt.show()
    plt.close()

    print("Graphs have been saved to the current folder.")

if __name__ == "__main__":
    # Register the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    start_time = time.time()

    # Start the multi-connection management thread
    connection_thread = threading.Thread(target=accept_connections)
    connection_thread.daemon = True
    connection_thread.start()

    # Start the throughput calculation thread
    throughput_thread = threading.Thread(target=calculate_throughput)
    throughput_thread.daemon = True
    throughput_thread.start()

    # Start the real-time metrics display thread
    metrics_thread = threading.Thread(target=print_metrics)
    metrics_thread.daemon = True
    metrics_thread.start()

    # Start packet sniffing in the main thread
    start_sniffing()
