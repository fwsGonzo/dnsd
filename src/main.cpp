/**
 * DNS message
 * +---------------------+
 * | Header              |
 * +---------------------+
 * | Question            | the question for the name server
 * +---------------------+
 * | Answer              | RRs answering the question
 * +---------------------+
 * | Authority           | RRs pointing toward an authority
 * +---------------------+
 * | Additional          | RRs holding additional information
 * +---------------------+
 * 
 * DNS header
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     ID                        |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   QDCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   ANCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   NSCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   ARCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 
**/

#include <string>
#include <vector>

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct dns_header_t
{
	unsigned short id;       // identification number
	unsigned char rd :1;     // recursion desired
	unsigned char tc :1;     // truncated message
	unsigned char aa :1;     // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1;     // query/response flag
	unsigned char rcode :4;  // response code
	unsigned char cd :1;     // checking disabled
	unsigned char ad :1;     // authenticated data
	unsigned char z :1;      // reserved, set to 0
	unsigned char ra :1;     // recursion available
	unsigned short q_count;    // number of question entries
	unsigned short ans_count;  // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count;  // number of resource entries
} __attribute__ ((packed));

struct dns_question_t
{
	unsigned short qtype;
	unsigned short qclass;
};

#pragma pack(push, 1)
struct dns_rr_data_t // resource record data
{
	unsigned short type;
	unsigned short _class;
	unsigned int   ttl;
	unsigned short data_len;
};
#pragma pack(pop)

#define DNS_PORT         53

#define DNS_QR_QUERY     0
#define DNS_QR_RESPONSE  1

#define DNS_TC_NONE    0 // no truncation
#define DNS_TC_TRUNC   1 // truncated message

#define DNS_CLASS_INET   1

#define DNS_TYPE_A    1  // A record
#define DNS_TYPE_NS   2  // respect mah authoritah
#define DNS_TYPE_ALIAS 5 // name alias

#define DNS_TYPE_SOA  6  // start of authority zone
#define DNS_TYPE_PTR 12  // domain name pointer
#define DNS_TYPE_MX  15  // mail routing information

#define DNS_Z_RESERVED   0

enum dns_resp_code_t
{
	NO_ERROR     = 0,
	FORMAT_ERROR = 1,
	SERVER_FAIL  = 2,
	NAME_ERROR   = 3,
	NOT_IMPL     = 4, // unimplemented feature
	OP_REFUSED   = 5, // for political reasons
};

struct dns_query_t // query structure
{
    char* name;
    dns_question_t* ques;
};

#define SOCKET_ERROR  -1
typedef int socket_t;

//List of DNS Servers registered on the system
std::vector<std::string> dns_servers;

void  dnsNameFormat(char* dns, const char* host);
char* readName(char* reader, char* buffer, int& count);
void  ngethostbyname(const char* host);

struct dns_rr_t // resource record
{
	dns_rr_t(char*& reader, char* buffer)
	{
		int stop;
		this->name = readName(reader, buffer, stop);
		reader += stop;
		
		this->resource = *(dns_rr_data_t*) reader;
		reader += sizeof(dns_rr_data_t);
		
		// if its an ipv4 address
		if (ntohs(resource.type) == DNS_TYPE_A)
		{
			int len = ntohs(resource.data_len);
			
			this->rdata = std::string(reader, len);
            reader += len;
        }
        else
        {
            this->rdata = readName(reader, buffer, stop);
            reader += stop;
        }
	}
	
    std::string name;
    std::string rdata;
    dns_rr_data_t resource;
    
    void print()
    {
        printf("Name: %s ", name.c_str());
		switch (ntohs(resource.type))
		{
		case DNS_TYPE_A:
			{
				long* p = (long*) rdata.c_str();
				sockaddr_in a;
				a.sin_addr.s_addr = *p;
				printf("has IPv4 address: %s", inet_ntoa(a.sin_addr));
			}
			break;
		case DNS_TYPE_ALIAS:
			printf("has alias: %s", rdata.c_str());
			break;
		case DNS_TYPE_NS:
            printf("has authoritative nameserver : %s", rdata.c_str());
            break;
        default:
			printf("has unknown resource type: %d", ntohs(resource.type));
		}
        printf("\n");
	}
};

class DnsRequest
{
public:
	DnsRequest()
	{
		this->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		
		// DNS server
		dest.sin_family      = AF_INET;
		dest.sin_port        = htons(DNS_PORT);
		
		this->buffer = new char[65536];
	}
	~DnsRequest()
	{
		delete[] this->buffer;
	}
	
	int  request(const std::string& server, const std::string& hostname);
	bool receive();
	
private:
	socket_t    sock;
	sockaddr_in dest;
	std::string server;
	std::string hostname;
	char*       buffer;
	dns_question_t* qinfo;
	
    std::vector<dns_rr_t> answers;
    std::vector<dns_rr_t> auth;
    std::vector<dns_rr_t> addit;
};

int main(void)
{
	dns_servers.emplace_back("8.8.8.8");
	dns_servers.emplace_back("8.8.4.4");
	
	DnsRequest req;
	// send request
	req.request("8.8.8.8", "www.google.com");
	// receive response
	req.receive();
	
}

unsigned short generateID()
{
	static unsigned short id = 0;
	return ++id;
}

int DnsRequest::request(const std::string& server, const std::string& hostname)
{
	this->server   = server;
	this->hostname = hostname;
	dest.sin_addr.s_addr = inet_addr(server.c_str());
	
	// fill with DNS request data
	dns_header_t* dns = (dns_header_t*) this->buffer;
	dns->id = generateID();
	dns->qr = DNS_QR_QUERY;
	dns->opcode = 0;       // standard query
	dns->aa = 0;           // not Authoritative
	dns->tc = DNS_TC_NONE; // not truncated
	dns->rd = 1; // recursion Desired
	dns->ra = 0; // recursion not available
	dns->z  = DNS_Z_RESERVED;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = dns_resp_code_t::NO_ERROR;
	dns->q_count = htons(1); // only 1 question
	dns->ans_count  = 0;
	dns->auth_count = 0;
	dns->add_count  = 0;
	
    // point to the query portion
	char* qname = this->buffer + sizeof(dns_header_t);
	
	// convert host to dns name format
	dnsNameFormat(qname, hostname.c_str());
	// length of dns name
	int namelen = strlen(qname) + 1;
	
	// set question to Internet A record
	this->qinfo   = (dns_question_t*) (qname + namelen);
	qinfo->qtype  = htons(DNS_TYPE_A); // ipv4 address
	qinfo->qclass = htons(DNS_CLASS_INET);
	
	printf("Sending Packet...");
	int sent = sendto(this->sock, this->buffer, sizeof(dns_header_t) + namelen + sizeof(dns_question_t), 0, (struct sockaddr*) &dest, sizeof(dest));
    
	if (sent == SOCKET_ERROR)
	{
		printf("error %d: %s\n", errno, strerror(errno));
		return errno;
    }
	printf("Sent!\n");
	return 0;
}


bool DnsRequest::receive()
{
    // read reply from DNS server
    socklen_t read_len = sizeof(dest);
    int readBytes = recvfrom(this->sock, this->buffer, 65536, 0, (struct sockaddr*) &dest, &read_len);
    
    printf("Receiving answer...");
    if (readBytes == SOCKET_ERROR)
    {
		printf("error %d: %s\n", errno, strerror(errno));
    }
    else if (readBytes == 0)
    {
		printf("closed prematurely\n");
		return false;
	}
    printf("Received.\n");
	
	dns_header_t* dns = (dns_header_t*) this->buffer;
	
    printf("The response contains:\n");
    printf(" %d questions\n", ntohs(dns->q_count));
    printf(" %d answers\n",   ntohs(dns->ans_count));
    printf(" %d authoritative servers\n", ntohs(dns->auth_count));
    printf(" %d additional records\n\n",  ntohs(dns->add_count));
	
	// move ahead of the dns header and the query field
	char* reader = ((char*) this->qinfo) + sizeof(dns_question_t);
	
	// reading answers
	int stop = 0;
	
    for(int i = 0; i < ntohs(dns->ans_count); i++)
    {
		answers.emplace_back(reader, buffer);
    }
 
    // read authorities
    for (int i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth.emplace_back(reader, buffer);
    }
 
    //read additional
    for (int i = 0; i < ntohs(dns->add_count); i++)
    {
		addit.emplace_back(reader, buffer);
    }
	
    // print answers
    for (auto& answer : answers)
		answer.print();
 
    // print authorities
    for (auto& a : auth)
		a.print();
	
    // print additional resource records
    for (auto& a : addit)
		a.print();
}

char* readName(char* reader, char* buffer, int& count)
{
    char* name = new char[256];
    unsigned p = 0;
    unsigned offset = 0;
    bool jumped = false;
	
    count = 1;
    name[0] = 0;
	
	unsigned char* ureader = (unsigned char*) reader;
	
    // read the names in 3www6google3com format
    while (*ureader)
    {
        if (*ureader >= 192)
        {
            offset = (*ureader) * 256 + *(ureader+1) - 49152; // = 11000000 00000000
            ureader = (unsigned char*) buffer + offset - 1;
            jumped = true; // we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *ureader;
        }
        ureader++;
		
		// if we havent jumped to another location then we can count up
        if (jumped == false) count++;
    }
	
    name[p] = '\0'; // zero-term
    
    // number of steps we actually moved forward in the packet
    if (jumped)
        count++;
	
    // now convert 3www6google3com0 to www.google.com
    int len = strlen(name);
    int i;
    for(i = 0; i < len; i++)
    {
        p = name[i];
        
        for(int j = 0; j < p; j++)
        {
            name[i] = name[i+1];
            i++;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot
	
    return name;
}

// convert www.google.com to 3www6google3com
void dnsNameFormat(char* dns, const char* hostn)
{
    int lock = 0;
	int len = strlen(hostn) + 1;
	
    char* copy = new char[len];
    strcpy(copy, hostn);
    strcat(copy, ".");
    
    for(int i = 0; i < len; i++)
    {
        if (copy[i] == '.')
        {
            *dns++ = i - lock;
            for(; lock < i; lock++)
            {
                *dns++ = copy[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}
