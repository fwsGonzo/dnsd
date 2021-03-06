#ifdef __linux__
#include "linux_dns.hpp"
#include <iostream>
int main(int argc, char** argv)
{
  if(argc < 2){
    std::cout << "Usage: " << argv[0] << " <nameserver IP>" << std::endl;
    return 0;
  }
  
  
	LinuxDNS dns;
	// set nameserver
	dns.set_ns(argv[1]);
	
	// dig up some dirt
	if (dns.request("www.google.com"))
		dns.print();
	if (dns.request("www.fwsnet.net"))
		dns.print();
	if (dns.request("www.vg.no"))
		dns.print();
	
	return 0;
}

#elif __includeOS__
#include <os>
#include "includeDNS.hpp"

void Service::start()
{
	IncludeDNS dns;
	
	// set nameserver
	dns.set_ns("8.8.8.8");
	
	// dig up some dirt
	if (dns.request("www.google.com"))
		dns.print();
	if (dns.request("www.fwsnet.net"))
		dns.print();
	if (dns.request("www.vg.no"))
		dns.print();
	
}

#endif
