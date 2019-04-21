from scapy.all import *
import sys
import json

# PCAP filename passed as parameter to program
file = sys.argv[1]
print('Reading contents of : ' + file)

# Reads into SCAPY format
packets = rdpcap(file)

# These are the defined layers and associated attributes in SCAPY
layers = ['CookedLinux','Ether','IP','TCP','Raw']
eth = ['src','dst','type']
ip = ['version','ihl','tos','len','id','flags','frag','ttl','proto','chksum',
      'src','dst']
icmp = ['type','code','chksum','id','seq']
raw = ['Raw']

# Objective 1: Read Packets into dict for export in JSON format
packet_dict = {}
data = {}
pid = 1
for packet in packets:
  for layer in layers:
    if(packet.haslayer(layer)):
      current = packet.getlayer(layer)
      if(layer=='IP'):
        data['IP'] = {
              'Source' : current.src,
	      'Destination' : current.dst,
              'Version' : current.version,
              'IHL' : current.ihl,
              'TOS' : current.tos,
              'LEN' : current.len,
              'ID' : current.id,
              #'Flags' : current.flags,
              'Frag' : current.frag,
              'TTL' : current.ttl,
              'Proto' : current.proto,
              'Chksum' : current.chksum
	}
      if(layer=='Ether'):
        data['Ethernet'] = {
	      'Source' : current.src,
              'Destination' : current.dst,
              'Type' : current.type
	}
      if(layer == 'ICMP'):
        data['ICMP'] = {
              'Type' : current.type,
	      'Chksum' : current.chksum,
              'Code' : current.code,
              'ID' : current.id,
              'Seq' : current.seq
	}
      if(layer == 'Raw'):
        data['Raw'] = {
              'Raw' : str(current).encode("HEX")
	}
  packet_dict[pid] = data
  pid += 1

print(json.dumps(packet_dict))
