from scapy.all import *
from util.WlanLogger import logger;
from concurrent import futures


SUCCESS_STATE = 0;
def association_process(STA, AP,elementTag = None):
	logger.info("association process will start");

	## initialization for multi-thread process.
	executor = futures.ThreadPoolExecutor(max_workers=2);

	## recieve process (worker 1)
	recv_thread = executor.submit(recv_association, STA, AP);

	## sender process (worker 2)
	send_thread = executor.submit(send_association, STA, AP,elementTag);

	send_thread.result();
	response_packet = recv_thread.result();

	if (response_packet[Dot11AssoResp].status == SUCCESS_STATE):
		logger.info("Association process successfully finished");
		return response_packet;
	else:
		logger.error("Association process was fail");

def send_association(STA, AP,elementTag = None):
	logger.info("sending an association request packet to " + AP.bssid + " (" + AP.essid + ") ...");

	packet = generate_association_packet(STA, AP,elementTag);
	STA.send_packet(packet);

	logger.info("An association request packet was sent to " + AP.bssid + " (" + AP.essid + ") ...");

def recv_association(STA, AP):
	logger.info("wait until I capture an authentication packet from " + AP.bssid + " (" + AP.essid + ") ...");
	packets = STA.recv_packet(filter=lambda x: (  (x.haslayer(Dot11AssoResp))) and (x[Dot11].addr2 == AP.bssid) and (STA.is_packet_for_me(x)));

	if(len(packets) == 0):
		logger.error("cannot capture an authentication packet from " + AP.bssid + " (" + AP.essid + ") ...");
		raise Exception("cannot capture an authentication packet packet from " + AP.bssid + " (" + AP.essid + ") ...");

	return packets[0];

def generate_association_packet(STA, AP,elementTag = None):
	logger.debug("generate a association request packet ")
	radiotap = STA.radiotap;
	dot11 = Dot11(addr1=AP.bssid, addr2=STA.mac_address, addr3=AP.bssid, FCfield=0);

	AssocReq = Dot11AssoReq(cap=0x0101, listen_interval=0x00a);
	if (elementTag):
		Tagged_param = Dot11Elt(ID=0, info="{}".format(AP.essid)) / STA.dot11_rates/elementTag;

	return radiotap/ dot11/AssocReq / Tagged_param;

class association():

	def __init__(self,STA,AP):
		self.STA = STA;
		self.AP = AP;
		self.SUCCESS_COMMAND = "assocenticated!";
		self.FAIL_COMMAND = "No assocenticated";
		self.state = self.FAIL_COMMAND;
	
	def assoc_process(self):
		logger.info("association process will start");



		packet = radiotap / dot11 / AssocReq / Tagged_param;
		
		self.state = self.FAIL_COMMAND;
		self.STA.assoc_found = False;

		jobs = list();

		result_queue = mp.Queue();
		receive_process = mp.Process(target=self.__recv_assoc, args = (result_queue,) );

		jobs.append(receive_process);

		send_process = mp.Process(target=self.__send_assoc,args=(packet,))
		jobs.append(send_process)

		for job in jobs:
	        	job.start();

		for job in jobs:
			job.join();
		if result_queue.get():
			self.state = self.SUCCESS_COMMAND;
        
		if (self.state == self.SUCCESS_COMMAND):
			logger.info("association process was successful")
		elif (self.state == self.FAIL_COMMAND):
			logger.error("association process was fail");
		else:
			logger.error("Unexpected error has occured")

	def __send_assoc(self,_packet):
	        logger.info("association packet will be sent");
        	sleep(0.4);
	        sendp(_packet,iface=self.STA.ifc_name,verbose=0);
        	logger.info("association packet was sent");

	def __recv_assoc(self,mp_queue):
        	sniff(iface=self.STA.ifc_name, lfilter=lambda x:x.haslayer(Dot11AssoResp),stop_filter=self.__check_assoc,timeout=5);
        	mp_queue.put(self.STA.assoc_found);

	def __check_assoc(self,packet):
        	seen_receiver = packet[Dot11].addr1;
	        seen_sender = packet[Dot11].addr2;
	        seen_bssid = packet[Dot11].addr3;
		
	        if (seen_receiver == self.STA.ifc_mac and seen_sender == self.AP.bssid and seen_bssid == self.AP.bssid):
        		self.STA.assoc_found = True;
		        logger.info("association packet was received")

	        return self.STA.assoc_found
            
if __name__ == "__main__":
	print("\n\n")
	print("")

	
	STA = STA_Interface(ifc_name="wlx9cc9eb21fa6e",ifc_mac="9c:c9:eb:21:fa:6e");
	AP = AP_Interface(bssid="18:ec:e7:5f:a2:04",essid = "Buffalo-A-A200-Open")

	s = association(STA,AP);
	s.assoc_process();




