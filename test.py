from scapy.all import *
import random
import sys

host = sys.argv[1]
port_range = [22,23,53, 631,80,443,3389,5000]

# Send SYN with random Src port for each Dst port
for dst_port in port_range:
  src_port = random.randint(1025,65534)
  resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0,)
  if resp is None:
    #print(f"{host}:{dst_port} is filtered (silently dropped).")
    print(host + ':' + str(dst_port) + 'is filtered (silently dropped).')
	
  elif(resp.haslayer(TCP)):
    if(resp.getlayer(TCP).flags == 0x12):
      # Send a RST to close the connection
      send_rst = sr(
        IP(dst=host)/TCP(sport=src_port,dport=dst_port, flags='R'),
        timeout=1,
	verbose=0,
	)
      print(host+':'+ str(dst_port) +' is open.')

    elif(resp.getlayer(TCP).flags == 0x14):
      print(host+':'+ str(dst_port) +' is closed.')
  
  elif(resp.haslayer(ICMP)):
    if(
      int(resp.getlayer(ICMP).type) == 3 and
      int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    ):
      print(host+':'+ str(dst_port) +' is filtered (silently dropped).')
