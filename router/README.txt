
We decided to structure our code so that the function -- sr_handlepacket() -- in sr_router.c would process packets the router receives by determining the type of protocol of the packet and calling their respective packet handler helper functions.

In the file sr_router.c, the functions -- sr_handleIPpacket() and sr_handleARPpacket() -- were implemented and called in sr_handlepacket().  A few other helper functions with more basic functionalities were implemented in other files and are called in sr_handleIPpacket() and sr_handleARPpacket() to help make them less convoluted.

In the file sr_arpcache.c, the helper function -- handle_arpreq() -- is implemented and called in sr_handleIPpacket() when a request is cached.  It is called again in sr_arpcache_sweepreqs() which is called every second, to go through all the requests on the ARP cache and handle_arpreq() is called on each request on the cache.  This function sends an ARP request out and keeps track of how many times the request has been sent.  If the request has been sent 5 times withoug a response, an ICMP packet type 3 code 1 will be sent back to the source.

In the file sr_rt.c, the function -- sr_find_routing_entry_int() -- was implemented to find the routing entry with the longest prefix.  This function is then caled in both sr_handleIPpacket() and ar_handleARPpacket to determine the interface the packet currently being handled should be sent out from.  

In the file sr_if.c, the function -- sr_get_interface_from_ip() -- was implement to find the interface entry of the provided ip address.  This function is also called in sr_handleIPpacket() and sr_handleARPpacket() to find the ip->mac mapping of the given ip address and return its sr_if struct if it exists. 

In the file sr_utils.c, the function -- createICMP() -- was implemented to create ICMP packets, depending on the type and code entered as parameters to the function.  This function is caled in sr_handleIPpacket() when the IP TTL dies with type 11 code 0, when no route to the destination IP is found with type 3 code 0 and if the received packet is IP TCP/UDP with type 3 code 3.  It is also called in s_arpcache.c in handle_arpreq() with type 3 code 1, when the request being processed has been sent out 5 times wthout a reply.  
