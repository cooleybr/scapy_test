This repository is designed to test reading PCAP data using the SCAPY library
test.py is a SCAPY tutorial for checking open ports based on IP
  - The IP is set to read from input when running the file
  - SUDO is required to run this command
  - Example sudo python test.py 192.168.0.1
analyze.py reads in a tcpdump PCAP file and parses contents to json for serialization
  - This script also uses the sys.argv parameters for getting filename (not included in git)
  - example execution python analyze.py test.pcap
