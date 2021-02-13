## Pseudo Wlan Connection Tool Set (Station side)


    This is a pseudo wlan connection tool set, which connects to an Access Point (AP) via Wi-Fi.
    It is written in Python 3 using the Scapy module.
    I develop the tool set to study 802.11 protocol.  

## Execution environment 

    Linux OS + Wifi USB adapter
    I use Ubuntu 20.10 and NETGEAR A6210 (Wifi USB adapter).

    **notes
        1. It is need to run with administrator priviledges. (because scapy needs administrator priviledges)

        2. A wifi USB adapter must have the following two functions.
            2.1 set a adapter to monitor mode.
            2.2 automatically send and receive 802.11 ACKs within the required timeout although a adapter is monitor mode.

        3. The mac address of packets which the tool set sends must be the mac address of a wifi USB adapter.
            (In order to satisfy the above 2.2)
　　　　　  	
## Functions (unfinished now)
 
    this tool connect to a Encryption method 

	The tool set send/receive the following packets.
		1. probe request/response
		2. authentication
		3. association request/ response
		4. 4-way handshake (not implement yet)
		5. DHCP client (discover, offer, request, ack) 
		6. ARP (request, response)
		7. PING (request, response)
		8. Deauthenitcation, Disassociation, QoS Null function.
		
    ** 4-way hand-shake protocol is successfully implemented, but an encrypted packet cannot be sent in this version.
 
    As a future work, I will develop WPA3 SAE protocol (authentication with SAE hand-shake).

## How to use
	
	


## Reference

 https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/
