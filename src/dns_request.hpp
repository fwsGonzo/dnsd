#ifndef DNS_REQUEST_HPP
#define DNS_REQUEST_HPP

#include "dns.hpp"

class AbstractRequest
{
public:
	AbstractRequest()
	{
		this->buffer = new char[65536];
	}
	~AbstractRequest()
	{
		delete[] this->buffer;
	}
	
	// create/open connection to remote part
	virtual void init(const std::string& nameserver) = 0;
	
	// send request and read response using send() and read()
	void request(const std::string& hostname)
	{
		DnsRequest req;
		
		// create request to nameserver
		int messageSize = req.createRequest(buffer, hostname);
		
		// send request (Linux)
		send(hostname, messageSize);
		
		// read response (Linux)
		read();
		
		// parse response from nameserver
		req.parseResponse(buffer);
	}
	
protected:
	virtual bool send(const std::string& hostname, int messageSize) = 0;
	virtual bool read() = 0;
	
	char* buffer;
};

#endif
