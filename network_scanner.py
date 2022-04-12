import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ipaddress", help="Specify IP range to be scanned")
    options = parser.parse_args()
    #if not options.ipaddress:
        #parser.error("[-] Please specify an IP range, use --help for more info.")
    return options.ipaddress

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #returns list with answered and unanswered ip's 
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)  
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

    
ip_range = get_arguments()
scan_result = scan(ip_range) 
print_result(scan_result)

### Helpful code:
#scapy.ls(scapy.ARP()) - outputs all the fields that can be used
#print(arp_request.summary()) - outputs: ARP who has 0.0.0.0 says 192.168.1.4
#arp_request_broadcast.show() - shows details of both ARP and Ether packet