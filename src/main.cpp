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

struct dns_rr_t // resource record
{
    unsigned char* name;
    dns_rr_data_t* resource;
    unsigned char* rdata;
};


struct dns_query_t // query structure
{
    unsigned char*  name;
    dns_question_t* ques;
};

#define DNS_PORT         53

#define DNS_QR_QUERY     0
#define DNS_QR_RESPONSE  1

#define DNS_TC_NONE    0 // no truncation
#define DNS_TC_TRUNC   1 // truncated message

#define DNS_CLASS_INET   1

#define DNS_TYPE_A    1  // A record
#define DNS_TYPE_NS   2  // respect mah authoritah

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

#define SOCKET_ERROR  -1
typedef int socket_t;

//List of DNS Servers registered on the system
std::vector<std::string> dns_servers;

void dnsNameFormat(unsigned char* dns, const char* host);
unsigned char* readName(unsigned char* reader, unsigned char* buffer, int* count);
void ngethostbyname(const char* host);

int main(void)
{
	dns_servers.emplace_back("8.8.8.8");
	dns_servers.emplace_back("8.8.4.4");
	
	ngethostbyname("www.google.com");
	
}

unsigned short generateID()
{
	static unsigned short id = 0;
	return ++id;
}

void ngethostbyname(const char* host)
{
	unsigned char* buf = new unsigned char[65536];
	
	//the replies from the DNS server
    dns_rr_t answers[20];
    dns_rr_t auth[20];
    dns_rr_t addit[20];
 
	dns_header_t*   dns   = nullptr;
	dns_question_t* qinfo = nullptr;
	
	socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
    //Configure the sockaddress structure with information of DNS server
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(DNS_PORT);
    
    // Set the dns server
    if (dns_servers.empty())
    {
        //Use the open dns servers - 208.67.222.222 and 208.67.220.220
        dest.sin_addr.s_addr = inet_addr("208.67.222.222");
    }
    else
    {
        // dns server found on system
        dest.sin_addr.s_addr = inet_addr(dns_servers[0].c_str());
    }
	
	// Set the DNS structure to standard queries
	dns = (dns_header_t*) buf;
	
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
	unsigned char* qname = buf + sizeof(dns_header_t);
	
	// convert host to dns name format
	dnsNameFormat(qname, host);
	qinfo = (dns_question_t*) (qname + strlen((const char*) qname) + 1);
	
    qinfo->qtype  = htons(DNS_TYPE_A); // ipv4 address
    qinfo->qclass = htons(DNS_CLASS_INET);
	
	printf("\nSending Packet...");
	int sent = sendto(s, (char*) buf, sizeof(dns_header_t) + (strlen((const char*) qname) + 1) + sizeof(dns_question_t), 0, (struct sockaddr*) &dest, sizeof(dest));
	if (sent == SOCKET_ERROR)
	{
		printf("error %d: %s\n", errno, strerror(errno));
    }
    printf("Sent");
	
    socklen_t read_len = sizeof(dest);
    int readBytes = recvfrom(s, (char*) buf, 65536, 0, (struct sockaddr*) &dest, &read_len);
    printf("\nReceiving answer...");
    if (readBytes == SOCKET_ERROR)
    {
		printf("error %d: %s\n", errno, strerror(errno));
    }
    else if (readBytes == 0)
    {
		printf("closed prematurely\n");
		return;
	}
    printf("Received.");
	
    dns = (dns_header_t*) buf;
	
	// move ahead of the dns header and the query field
	unsigned char* reader = ((unsigned char*) qinfo) + sizeof(dns_question_t);
	
    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.",   ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",  ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));
	
	// reading answers
	int stop = 0;
	
    for(int i = 0; i < ntohs(dns->ans_count); i++)
    {
        answers[i].name = readName(reader, buf, &stop);
        reader += stop;
		
        answers[i].resource = (dns_rr_data_t*) reader;
        reader += sizeof(dns_rr_data_t);
		
		// if its an ipv4 address
		if (ntohs(answers[i].resource->type) == DNS_TYPE_A)
        {
            int len = ntohs(answers[i].resource->data_len);
            
            answers[i].rdata = (unsigned char*) malloc(len + 1);
			
            for(int j = 0; j < len; j++)
				answers[i].rdata[j] = reader[j];
			
            answers[i].rdata[len] = '\0';
			
            reader = reader + ntohs(answers[i].resource->data_len);
			
        }
        else
        {
            answers[i].rdata = readName(reader,buf,&stop);
            reader = reader + stop;
        }
 
    }
 
    //read authorities
    for (int i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth[i].name = readName(reader, buf, &stop);
        reader+=stop;
		
        auth[i].resource = (dns_rr_data_t*) reader;
        reader += sizeof(dns_rr_data_t);
		
        auth[i].rdata = readName(reader, buf, &stop);
        reader += stop;
    }
 
    //read additional
    for (int i = 0; i < ntohs(dns->add_count); i++)
    {
		addit[i].name = readName(reader, buf, &stop);
		reader += stop;
		
        addit[i].resource = (dns_rr_data_t*) reader;
        reader += sizeof(dns_rr_data_t);
		
        if (ntohs(addit[i].resource->type) == DNS_TYPE_A)
        {
			int len = ntohs(addit[i].resource->data_len);
			
			addit[i].rdata = new unsigned char[len + 1];
			memcpy(addit[i].rdata, reader, len);
			addit[i].rdata[len] = '\0';
			
			reader += len;
		}
		else
		{
			addit[i].rdata = readName(reader, buf, &stop);
			reader += stop;
		}
    }
	
	struct sockaddr_in a;
	
    //print answers
    for (int i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name: %s ", answers[i].name);
		
        switch (ntohs(answers[i].resource->type))
        {
		case DNS_TYPE_A: // IPv4 address
			{
				long* p = (long*) answers[i].rdata;
				a.sin_addr.s_addr = *p; //working without ntohl
				printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
			}
			break;
		case 5: // alias
            printf("has alias name : %s", answers[i].rdata);
			break;
		default:
			printf("unknown answer type: %d", ntohs(answers[i].resource->type));
		}
        printf("\n");
    }
 
    //print authorities
    for (int i = 0; i < ntohs(dns->auth_count); i++)
    {
        printf("Name: %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == DNS_TYPE_NS)
        {
            printf("has authoritative nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }
 
    //print additional resource records
    for(int i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Additional: %s ",addit[i].name);
        
        if (ntohs(addit[i].resource->type) == DNS_TYPE_A)
        {
            long* p = (long*) addit[i].rdata;
            a.sin_addr.s_addr = *p; //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
}

unsigned char* readName(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char* name = new unsigned char[256];
    unsigned p = 0;
    unsigned offset = 0;
    bool jumped = false;
	
    *count = 1;
    name[0] = 0;
	
    // read the names in 3www6google3com format
    while (*reader)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader+1) - 49152; // = 11000000 00000000
            reader = buffer + offset - 1;
            jumped = true; // we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }
        reader++;
		
		// if we havent jumped to another location then we can count up
        if (jumped == false) *count += 1;
    }
	
    name[p] = '\0'; // zero-term
    
    // number of steps we actually moved forward in the packet
    if (jumped)
        *count += 1;
	
    // now convert 3www6google3com0 to www.google.com
    int len = strlen((const char*) name);
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
void dnsNameFormat(unsigned char* dns, const char* hostn)
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
