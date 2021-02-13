from scapy.all import *
from util.WlanLogger import logger
from concurrent import futures

SUCCESS_STATE =0;


def authentication_process(STA, AP):
	logger.info("authentication process will start");

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_authentication, STA, AP);

	## sender process (worker 2)
	send_thread = executor.submit(send_authentication, STA, AP);

	send_thread.result();
	response_packet = recv_thread.result();

	if (response_packet[Dot11Auth].status == SUCCESS_STATE):
		logger.info("An authentication process successfully finished");
		return response_packet;
	else:
		logger.error("An authentication process was fail");

def send_authentication(STA, AP):
	logger.info("sending an authentication packet to " + AP.bssid + " (" + AP.essid + ") ...");

	packet = generate_authentication_packet(STA, AP);
	STA.send_packet(packet);

	logger.info("An authentication packet was sent to " + AP.bssid + " (" + AP.essid + ") ...");

def recv_authentication(STA, AP):
	logger.info("wait until I capture an authentication packet from " + AP.bssid + " (" + AP.essid + ") ...");
	packets = STA.recv_packet(filter=lambda x: (  (x.haslayer(Dot11Auth)) and (x[Dot11].addr2 == AP.bssid) and (STA.is_packet_for_me(x))));

	if(len(packets) == 0):
		logger.error("cannot capture an authentication packet from " + AP.bssid + " (" + AP.essid + ") ...");
		raise Exception("cannot capture an authentication packet packet from " + AP.bssid + " (" + AP.essid + ") ...");

	return packets[0];

def generate_authentication_packet(STA,AP):
	return  STA.radiotap / Dot11(addr1=AP.bssid, addr2=STA.mac_address, addr3=AP.bssid, FCfield=0) / Dot11Auth(algo=0, seqnum=0x0001, status=0x0000);


