from scapy.all import *
from concurrent import futures
from util.WlanLogger import logger

OP_REQUEST_CODE = 1;
OP_RESPONSE_CODE = 2;
OP_MASSAGE_HASH = {1:"request",2:"response"}

def arp_sender_process(STA,AP,Target):
	logger.info("ARP request process starts")

	## generate an ARP request packet.
	arp_requested_packet = generate_arp_request_packet(STA,AP,Target.IP_address);

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_arp_response_packet, STA, AP, Target.IP_address);

	## sender process (worker 2)
	logger.info("send an ARP request packet.");
	send_thread = executor.submit(STA.send_packet, arp_requested_packet);

	send_thread.result();
	response_packet = recv_thread.result();

	if (response_packet):
		logger.info("An ARP response packet was successfully received");
		logger.info("ARP massage: "+Target.IP_address + " is at " + response_packet[ARP].hwsrc);
		return response_packet;
	else:
		logger.error("An ARP response DHCP offer packet was not received");


def arp_response_process(src,dst,AP):
	logger.info("An ARP response process starts")

	## receive an arp request packet from dst.
	request_packet = recv_arp_request_packet(src,dst, AP);

	if (not request_packet):
		logger.error("cannot capture an ARP request packet");
		return ;

	response_packet = generate_arp_response_packet(src, AP,request_packet);
	src.send_packet(response_packet);
	logger.info("An ARP response process successfully finished");

def recv_arp_request_packet(src,dst, AP):
	logger.info("wait until I capture an arp request packet from " + dst.mac_address);
	packets = src.recv_packet(filter=lambda x: ((x.haslayer(ARP)) and (x[ARP].op == OP_REQUEST_CODE) and (x[ARP].hwsrc == dst.mac_address)and  (AP.is_packet_transmitted_by_me(x)) and (src.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot capture an arp request from " + AP.bssid + " (" + AP.essid + ") .");
		return;

	return packets[0];

def recv_arp_response_packet(src, AP, IP_addr):
	logger.info("wait until I capture an arp response packet from " + IP_addr);
	packets = src.recv_packet(filter=lambda x: ((x.haslayer(ARP)) and (x[ARP].op == OP_RESPONSE_CODE) and (x[ARP].psrc == IP_addr) and (AP.is_packet_transmitted_by_me(x)) and (src.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot capture an arp response from " + AP.bssid + " (" + AP.essid + ") .");
		return;

	return packets[0];


def generate_arp_response_packet(src,AP,ARP_request_packet):
	logger.debug("generate an ARP response packet");

	## layer 1
	Radiotap = src.radiotap

	## layer 2 (802.11)
	Dot11_Header = Dot11(addr1=AP.bssid, addr2=src.mac_address, addr3=ARP_request_packet[Dot11].addr3, FCfield=0x01, subtype=8,
						 type=2) / Dot11QoS();
	llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
	snap_header = SNAP(OUI=0x000000, code=0x0806)

	arp_header = ARP_request_packet[ARP].copy();

	arp_header.op = OP_RESPONSE_CODE;
	arp_header.pdst = arp_header.psrc;
	arp_header.hwdst = arp_header.hwdst;
	arp_header.psrc = src.IP_address;
	arp_header.hwsrc = src.mac_address;
	return Radiotap/Dot11_Header/llc_header/snap_header/arp_header;

def generate_arp_request_packet(STA, AP, requested_ip_addr):
	logger.debug("generate an ARP request packet");

	## layer 1
	Radiotap = STA.radiotap

	## layer 2 (802.11)
	Dot11_Header = Dot11(addr1=AP.bssid, addr2=STA.mac_address, addr3="ff:ff:ff:ff:ff:ff", FCfield=0x01, subtype=8, type=2) / Dot11QoS();
	llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
	snap_header = SNAP(OUI=0x000000, code=0x0806)

	## layer 2 (arp)
	arp_header = ARP(hwlen=6, plen=4, op=OP_REQUEST_CODE, hwsrc=STA.mac_address, psrc=STA.IP_address,
					 pdst=requested_ip_addr);

	return Radiotap / Dot11_Header / llc_header / snap_header / arp_header