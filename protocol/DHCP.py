from scapy.all import *
from concurrent import futures
from util.WlanLogger import logger

DISCOVER_MASSAGE = 1;
OFFER_MASSAGE = 2;
REQUEST_MASSAGE = 3;
ACK_MASSAGE = 5;
DHCP_OPTION_END_MASSAGE = 'end';

DHCP_CLIENT_PORT = 68;
DHCP_SERVER_PORT = 67;

def extract_dhcp_massage_from_packet(packet):
	return [option[1] for option in packet[DHCP].options if option[0] == "message-type"][0]

def DHCP_cliend_process(STA,AP):

	discover_packet = generate_discover_packet(STA, AP);

	offer_packet = DHCP_discover_offer_process(STA,AP,discover_packet);

	requested_packet = generate_dhcp_req_packet(discover_packet,offer_packet);

	ack_packet = DHCP_request_ack_process(STA, AP, requested_packet);

	set_IPaddress_TO_STA(STA,offer_packet);

	return discover_packet,offer_packet,requested_packet,ack_packet;

def DHCP_discover_offer_process(STA, AP, discover_packet):

	logger.info("DHCP discover-offer process will start");

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_dhcp_packet, STA, AP, OFFER_MASSAGE);

	## sender process (worker 2)
	logger.info("sending a DHCP discover packet.");
	send_thread = executor.submit(STA.send_packet, discover_packet);

	send_thread.result();
	response_packet = recv_thread.result();

	extract_dhcp_massage_from_packet(response_packet);

	if (extract_dhcp_massage_from_packet(response_packet) == OFFER_MASSAGE):
		logger.info("A DHCP offer packet was successfully received");
		return response_packet;
	else:
		logger.error("A DHCP offer packet was not received");

def DHCP_request_ack_process(STA, AP, offer_packet):

	logger.info("DHCP request-ack process will start");

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_dhcp_packet, STA, AP, ACK_MASSAGE);

	## sender process (worker 2)
	logger.info("sending a DHCP request packet.");
	send_thread = executor.submit(STA.send_packet, offer_packet);

	send_thread.result();
	response_packet = recv_thread.result();

	extract_dhcp_massage_from_packet(response_packet);

	if (extract_dhcp_massage_from_packet(response_packet) == ACK_MASSAGE):
		logger.info("A DHCP Ack packet was successfully received");
		return response_packet;
	else:
		logger.error("A DHCP Ack packet was not received");


def recv_dhcp_packet(STA,AP, dhcp_massage,xid=0x12345678):
	logger.info("wait until I capture a DHCP offer packet from DHCP server");

	packets = STA.recv_packet(filter=lambda x: ((x.haslayer(DHCP))) and (extract_dhcp_massage_from_packet(x) == dhcp_massage) and  (x[Dot11].addr2 == AP.bssid) and (STA.is_packet_for_me(x)));

	return packets[0]

def generate_discover_packet(STA,AP,xid=0x12345678):
		logger.debug("generate a DHCP discover packet.");

		Radiotap = STA.radiotap;

		Dot11_Header = Dot11(addr1=AP.mac_address, addr2=STA.mac_address, addr3="ff:ff:ff:ff:ff:ff", FCfield=0x01, subtype=8, type=2) / Dot11QoS();

		llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
		snap_header = SNAP(OUI=0x000000, code=ETH_P_IP)

		IP_Head = IP(src="0.0.0.0", dst="255.255.255.255");

		UDP_Head = UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT);
		BOOTP_Head = BOOTP(chaddr=mac2str(STA.mac_address), xid=xid);

		DHCP_option = [('message-type', DISCOVER_MASSAGE)];
		DHCP_option.append(DHCP_OPTION_END_MASSAGE)

		DHCP_Head = DHCP(options=DHCP_option);

		discover_packet = Radiotap / Dot11_Header / llc_header / snap_header / IP_Head / UDP_Head / BOOTP_Head / DHCP_Head;

		return discover_packet

def generate_dhcp_req_packet(discover_packet,offer_packet):
		request_packet = discover_packet.copy();
		request_packet[DHCP].options = offer_packet[DHCP].options.copy();
		massage_type_index = [index for index,option in enumerate(discover_packet[DHCP].options) if option[0] == "message-type"][0];
		request_packet[DHCP].options[massage_type_index] = ("message-type",REQUEST_MASSAGE);
		end_index = [index for index,option in enumerate(discover_packet[DHCP].options) if option == "end"][0];
		request_packet[DHCP].options.insert(end_index,('requested_addr',offer_packet[BOOTP].yiaddr));
		return request_packet;


def set_IPaddress_TO_STA(STA, dhcp_offer_packet):
	logger.info("setting IP_information to STA...");

	bootp_header = dhcp_offer_packet[BOOTP];
	dhcp_header = dhcp_offer_packet[DHCP];

	STA.IP_address = bootp_header.yiaddr;
	STA.subnet_mask = [option[1] for option in dhcp_header.options if option[0] == "subnet_mask"][0];
	STA.dns_server = [option[1] for option in dhcp_header.options if option[0] == "name_server"][0];
	STA.router = [option[1] for option in dhcp_header.options if option[0] == "router"][0];
	STA.lease_time = [option[1] for option in dhcp_header.options if option[0] == "lease_time"][0];

	logger.info("");
	logger.info("obtained IP information is as follow");
	logger.info("------------- obtain IP information --------------");
	logger.info("IP addr: " + STA.IP_address);
	logger.info("subnet_mask: " + STA.subnet_mask);
	logger.info("router: " + STA.router);
	logger.info("DNS server:" + STA.dns_server);
	logger.info("lease_time:" + str(STA.lease_time));
	logger.info("----------------------------------------------------");

