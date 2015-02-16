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
	virtual void set_ns(const std::string& nameserver) = 0;
	
	// send request and read response using send() and read()
	bool request(const std::string& hostname)
	{
		// create request to nameserver
		int messageSize = req.createRequest(buffer, hostname);
		
		// send request (Linux)
		if (!send(hostname, messageSize))
			return false;
		
		// read response (Linux)
		if (!read())
			return false;
		
		// parse response from nameserver
		req.parseResponse(buffer);
		return true;
	}
	void print()
	{
		// print all the (currently) stored information
		req.print(buffer);
	}
	
protected:
	virtual bool send(const std::string& hostname, int messageSize) = 0;
	virtual bool read() = 0;
	
	DnsRequest req;
	char*      buffer;
};

#endif
