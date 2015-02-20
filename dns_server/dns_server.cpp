#include "dns_server.hpp"

using namespace net;
using namespace std;

void DNS_server::start(Inet* net)
{
  cout << "Starting DNS server on port " << DNS::DNS_SERVICE_PORT << ".." << endl;
  this->network = net;
  
  auto del(upstream::from<DNS_server, &DNS_server::listener>(this));
  net->udp_listen(DNS::DNS_SERVICE_PORT, del);
}

// cheap implementation of ntohs/htons
unsigned short ntohs(unsigned short sh)
{
	unsigned char* B = (unsigned char*) &sh;
	
	return  ((0xff & B[0]) << 8) |
			((0xff & B[1]));
}
#define htons ntohs

int DNS_server::listener(std::shared_ptr<net::Packet>& pckt)
{
  cout << "<DNS SERVER> got packet..." << endl;
  
  DNS::full_header* full_hdr = (DNS::full_header*)pckt->buffer();
  DNS::header& hdr = full_hdr->dns_header;
  
  int packetlen = DNS::createResponse(hdr,
  [this] (const std::string& name) ->
  std::vector<IP4::addr>*
  {
    auto it = lookup.find(name);
    if (it == lookup.end()) return nullptr;
    return &lookup[name];
  });
  
  // send response back to client
  UDP::full_header& udp = full_hdr->full_udp_header;
  
  // set source & return address
  udp.udp_hdr.dport = udp.udp_hdr.sport;
  udp.udp_hdr.sport = htons(DNS::DNS_SERVICE_PORT);
  udp.udp_hdr.length = htons(sizeof(DNS::full_header) + packetlen);
  
  // Populate outgoing IP header
  udp.ip_hdr.daddr = udp.ip_hdr.saddr;
  udp.ip_hdr.saddr = network->ip4(ETH0);
  udp.ip_hdr.protocol = IP4::IP4_UDP;
  
  // packet length (??)
  int res = pckt->set_len(sizeof(UDP::full_header) + packetlen); 
  if(!res)
    cout << "<DNS_SERVER> ERROR setting packet length failed" << endl;
  std::cout << "Returning " << packetlen << "b to " << udp.ip_hdr.daddr.str() << std::endl;  
  std::cout << "Full packet size: " << pckt->len() << endl;
  // return packet (as DNS response)
  network->udp_send(pckt);
  
  return 0;
}
