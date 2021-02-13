from util.WlanLogger import logger;
from STA_AP_Interface import STA_Interface, AP_Interface, Interface
from scapy.all import *
from protocol.ARP import OP_REQUEST_CODE,OP_RESPONSE_CODE,generate_arp_response_packet
import protocol.ICMP as icmp;
import random
import threading
WAIT_TIME = 3600

class Task_Thread(threading.Thread):

    def __init__(self,STA, AP,packet):
        super(Task_Thread, self).__init__();
        self.id = random.randint(0,65535)
        self.STA = STA;
        self.AP = AP;
        self.packet = packet;

    def run(self):
        befMassage ="[No. "+str(self.id)+"] ";
        logger.info(befMassage+"I received a packet");

        if (self.packet.haslayer(ARP) and self.packet[ARP].pdst== self.STA.IP_address and self.packet[ARP].op == OP_REQUEST_CODE):
            logger.info(befMassage+"The received packet is an ARP response packet");
            response_packet = generate_arp_response_packet(self.STA, self.AP, self.packet);
            self.STA.send_packet(response_packet);
            logger.info(befMassage + "sent an ARP response packet successfully");

        elif (self.packet.haslayer(ICMP) and (self.packet[ICMP].type == icmp.ICMP_TYPE_REQUEST)):
            logger.info(befMassage + "The received packet is an ICMP request packet");
            response_packet = icmp.generate_icmp_response_packet(self.STA,self.AP,self.packet);
            self.STA.send_packet(response_packet);
            logger.info(befMassage + "sent an ICMP response packet successfully");
        else:
            logger.info(befMassage+"not implement this packet ["+self.packet.summary()+"]");

        logger.info("[No. " + str(self.id) + "] "+ "finish process");

def auto_receiver(STA, AP):
    taskContainer = [];
    try:
        while True:
            logger.info("waiting for a packet...")
            recv_packet = STA.recv_packet(filter=lambda x: (STA.is_packet_for_me(x) and (not x.haslayer(Dot11Beacon))),timeout = WAIT_TIME);

            if recv_packet:
                task_thread = Task_Thread(STA,AP,recv_packet[0]);
                taskContainer.append(task_thread);
                task_thread.start();

    except KeyboardInterrupt:
        print("try Exec")
        logger.info("Interruption has occurred.");
        logger.info("Stop auto receiver process");
        return;
    except Exception as e:
        from traceback import print_exc
        print_exc()
        logger.error("unexpected error has occurred.");
        logger.error("Stop auto receiver process");


if __name__ == "__main__":
    ifc_name = "wlx9cc9eb21fa6e";
    ifc_mac = "9c:c9:eb:21:fa:6e"
    STA = STA_Interface(ifc_name, ifc_mac);
    STA.IP_address = "192.168.11.2"
    AP = AP_Interface(bssid="18:ec:e7:5f:a2:04", essid="Buffalo-A-A200-Open");
    INTERFACE = Interface("b0:ca:68:21:38:61", "192.168.11.3");
    auto_receiver(STA,AP);
    #ls(ICMP);
