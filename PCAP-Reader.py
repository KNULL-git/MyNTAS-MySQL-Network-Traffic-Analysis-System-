import dpkt
import socket
from colorama import Fore

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

for ts,pkt in dpkt.pcap.Reader(open("")):
    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt)
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip=eth.data
    ipcounter+=1
    print(Fore.RESET + 'Source: ' + socket.inet_ntoa(ip.src)+'Destination: '+socket.inet_ntoa(ip.dst))
    if ip.p==dpkt.ip.IP_PROTO_TCP:
        tcpcounter+=1

    elif ip.p==dpkt.ip.IP_PROTO_UDP:
        udpcounter+=1

def printPCAP(pcap):
    for (ts,pkt) in dpkt.pcap.Reader(open("",'rb')):
        try:
            eth=dpkt.ethernet.Ethernet(pkt)
            ip= eth.data
            src= socket.inet_ntoa(ip.src)
            dst= socket.inet_ntoa(ip.dst)
            print('Source: '+ src + 'Destination: '+ dst)
        except:
            pass


print(Fore.RED + "Total number of packets in the pcap file:", counter)
print(Fore.YELLOW + "Total number of ip packets in the pcap file:", ipcounter)
print(Fore.MAGENTA + "Total number of tcp packets in the pcap file:", tcpcounter)
print(Fore.GREEN + "Total number of udp packets in the pcap file:", udpcounter)
printPCAP("")