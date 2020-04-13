UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

##TODO
Name: Ziying Yu
UID: 105182320

The high level design of your implementation:
Once received the packet, we have to parse the ethernet header and check it type;

if the type is arp:
	if it is an arp request: we have to send an arp reply
	if it is an arp reply: we have to store the ip-mac mapping into routing table and send the all 				       cached packets out

if the type is ipv4:	
	verify ipv4 checksum and ipv4 length
	check destination ip
		if the packet's destination ip is found:
			if it is the icmp packet, then verify the icmp checksum and send icmp 				echo reply;else we have to discard the packet
		if the destination is not found, we have to forward the packet:
			first update the header, verify the ttl and the checksum
			second, we have to lookup into the routing tablet find the next hop
			third, we have to lookup the arp cache:
				if we found the entry, forward the packet;  else, cache the 					packet and send arp request

The problems you ran into and how you solved the problems:

One of the questions i run into is that i ran into segmentation fault when i test the large file. It end up that i did not check the if the arp cache entry is valid or not. if the entry is not found, the we need to queue the request to the arp cache.
