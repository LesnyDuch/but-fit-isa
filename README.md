# but-fit-isa
### Python script that shows DHCPv4 network statistics.

  dhcp.py is a Python script that sniffs out DHCPv4 packets on ports 67 and 68 using all available network interfaces (each interface monitoring runs in a separate thread) except loopback, or networks passed by the user (an unavailable device is handled by an error).
  
  Once a device is given an IP address by the server the script checks if it belongs to a subnetwork whose address was passed as a console argument to the script by the user. With this information the script calculates statistics (maximal number of hosts, currently allocated addresses, percentage of utilization) of each network and prints it out to the console.  

  If a client device's lease time runs out, its address is removed from active network list and as such is not accounted for in the statistics. Also if a client sends a RELEASE message it is removed from active network list.
