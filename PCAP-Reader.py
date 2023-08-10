import socket
import mysql.connector
from scapy.all import *

# MySQL server credentials
mysql_host = "mysql_host_name"
mysql_user = "mysql_user_name"
mysql_password = "mysql_password"
mysql_database = "mysql_database"

# Establish MySQL connection
try:
    mysql_conn = mysql.connector.connect(
        host=mysql_host,
        user=mysql_user,
        password=mysql_password,
        database=mysql_database
    )
    mysql_cursor = mysql_conn.cursor()
    print("Connected to MySQL server")
except mysql.connector.Error as err:
    print("Error connecting to MySQL server:", err)
    exit()

# Create tables for each protocol
protocols = ['tcp', 'udp', 'ipv4', 'ipv6', 'icmp', 'arp', 'dns', 'dhcp']

for protocol in protocols:
    create_table_query = f"""
    CREATE TABLE IF NOT EXISTS {protocol}_packets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        source_ip VARCHAR(45),
        destination_ip VARCHAR(45),
        source_port INT,
        destination_port INT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    mysql_cursor.execute(create_table_query)
    mysql_conn.commit()
    print(f"Table {protocol}_packets created")

# Read pcap file
packets = rdpcap("pcap_file_with_the_complete_path.pcap")

# Process and store packets
for pkt in packets:
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    protocol = None
    if TCP in pkt:
        protocol = 'tcp'
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        print(f"TCP Packet - Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")
    elif UDP in pkt:
        protocol = 'udp'
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        print(f"UDP Packet - Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")
    elif IP in pkt:
        protocol = 'ipv4'
        print(f"IPv4 Packet - Source: {src_ip}, Destination: {dst_ip}")
    elif IPv6 in pkt:
        protocol = 'ipv6'
        print(f"IPv6 Packet - Source: {src_ip}, Destination: {dst_ip}")
    elif ICMP in pkt:
        protocol = 'icmp'
        print(f"ICMP Packet - Source: {src_ip}, Destination: {dst_ip}")
    elif ARP in pkt:
        protocol = 'arp'
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        print(f"ARP Packet - Source IP: {src_ip}, Destination IP: {dst_ip}")
    elif DNS in pkt:
        protocol = 'dns'
        print(f"DNS Packet - Source IP: {src_ip}, Destination IP: {dst_ip}")
    elif DHCP in pkt:
        protocol = 'dhcp'
        print(f"DHCP Packet - Source IP: {src_ip}, Destination IP: {dst_ip}")
    else:
        protocol = 'unknown'
        print("Unknown Packet")

    # Insert packet information into appropriate protocol table
    if protocol != 'unknown':
        insert_query = f"""
        INSERT INTO {protocol}_packets (source_ip, destination_ip, source_port, destination_port)
        VALUES (%s, %s, %s, %s)
        """
        values = (src_ip, dst_ip, src_port, dst_port)
        mysql_cursor.execute(insert_query, values)
        mysql_conn.commit()

# Close MySQL connection
mysql_cursor.close()
mysql_conn.close()
