#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <vector>

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <cstring>
#include <cryptopp/config.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <unordered_map>

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

std::string secr = "thegreatsovietrevolution";
const byte* key = (const byte*) secr.data();
byte iv[CryptoPP::AES::BLOCKSIZE];
std::unordered_map<uint32_t, int> address_to_socket_tcp;

struct addr_cast {
    union {
        unsigned char num[4];
        __be32 mem;
    };
};

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) {
          throw std::runtime_error("Issue while packet header");
    }

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
     if (len < 0) {
          throw std::runtime_error("Cant get payload data");
    }
   
    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    if (pkBuff == nullptr) {
          throw std::runtime_error("Issue while pktb allocate");
    }
    
    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up
    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    if (ip == nullptr) {
          throw std::runtime_error("Issue while ipv4 header parse");
    }
    //printf("sadress=%pI4\n", ip->saddr);
    //printf("dadress=%pI4\n", ip->daddr);
    int desc = nfq_ip_set_transport_header(pkBuff, ip);
    if (desc < 0) {
         throw std::runtime_error("Cant set transport header.");
    }

    if(ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        if (tcp == nullptr) {
            throw std::runtime_error("Issue while tcp header.");
        }

        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        if (payload == nullptr) {
            throw std::runtime_error("Issue while payload.");
        }

        payloadLen -= 4 * tcp->th_off;
        if (payloadLen <= 4) return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
        unsigned char *user_data = (unsigned char *)payload;

        int jj = 0;

        bool REDIRECT = true;
        bool is_encrypted = true;

        struct addr_cast *cst = (struct addr_cast*)malloc(sizeof(struct addr_cast));
        cst->mem = ip->saddr;
        unsigned char t0 = cst->num[0];
        unsigned char t1 = cst->num[1];
        unsigned char t2 = cst->num[2];
        unsigned char t3 = cst->num[3];

        //printf("%d.%d.%d.%d\n", (int)t0, (int)t1, (int)t2, (int)t3);
        //134.0.117.159

        struct addr_cast *recst = (struct addr_cast*)malloc(sizeof(struct addr_cast));

        if (REDIRECT) {
            if (is_encrypted) {
            	std::string ciphertext;
            	std::string decryptedtext;
            	for (unsigned int i = 0; i < payloadLen; i++) {
            		ciphertext.push_back(user_data[i]);
            	}
            	CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
            	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

            	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
            	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
            	stfDecryptor.MessageEnd();
            	for (unsigned int i = 0; i < payloadLen; i++) {
            		if (i < decryptedtext.size()) {
            			user_data[i] = decryptedtext[i];
            		} else {
            			user_data[i] = ' ';
            		}
            	}
            	
            	for (unsigned int i = decryptedtext.size() - 4; i < decryptedtext.size(); i++) {
		        recst->num[i - decryptedtext.size() + 4] = user_data[i];
		        printf("%d.", user_data[i]);
		        user_data[i] = ' ';
		}
		
		ip->daddr = recst->mem;
		
		int count = address_to_socket_tcp.count(ip->daddr);
	        int s;
	        if (count == 0) {
	            s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	            if (s == -1) {
	                printf("Failed to create socket :(\n");
	                exit(1);
	            }

	            struct sockaddr_in server;

	            server.sin_addr.s_addr = ip->daddr;
	            server.sin_family = AF_INET;
	            server.sin_port = htons(80);

	            //IP_HDRINCL to tell the kernel that headers are included in the packet
	            int one = 1;
	            const int *val = &one;

	            if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
	                perror("Error setting IP_HDRINCL");
	                exit(0);
	            }

	            if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                printf("BAD\n");
	                return 1;
	            }

	            if (sendto (s, pktb_data(pkBuff), pktb_len(pkBuff), 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                perror("sendto failed");
	            }
	            address_to_socket_tcp.insert(std::make_pair(ip->daddr, s));
	        } else {
	            auto mp = address_to_socket_tcp.find(ip->daddr);
	            //printf("old socket = %d   %u   ", mp->first, mp->second);
	            struct sockaddr_in server;

	            server.sin_addr.s_addr = ip->daddr;
	            server.sin_family = AF_INET;
	            server.sin_port = htons(80);
	            if (sendto (s, pktb_data(pkBuff), pktb_len(pkBuff), 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                perror("sendto failed");
	            }
	        }
		
		nfq_ip_set_checksum(ip);
		nfq_tcp_compute_checksum_ipv4(tcp, ip);
		free(cst);
		free(recst);
		printf("%d\n", pktb_len(pkBuff));
		return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
            } else {
		    for (unsigned int i = payloadLen - 4; i < payloadLen; i++) {
		        recst->num[i - payloadLen + 4] = user_data[i];
		        printf("%d.", user_data[i]);
		        user_data[i] = ' ';
		    }
		    ip->daddr = recst->mem;

		    int count = address_to_socket_tcp.count(ip->daddr);
	            int s;
	            if (count == 0) {
	                s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	                if (s == -1) {
	                    printf("Failed to create socket :(\n");
	                    exit(1);
	                }

	                struct sockaddr_in server;

	                server.sin_addr.s_addr = ip->daddr;
	                server.sin_family = AF_INET;
	                server.sin_port = htons(80);

	                //IP_HDRINCL to tell the kernel that headers are included in the packet
	                int one = 1;
	                const int *val = &one;

	                if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
	                    perror("Error setting IP_HDRINCL");
	                    exit(0);
	                }

	                if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                    printf("BAD\n");
	                    return 1;
	                }

	                if (sendto (s, pktb_data(pkBuff), pktb_len(pkBuff), 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                    perror("sendto failed");
	                }
	                address_to_socket_tcp.insert(std::make_pair(ip->daddr, s));
	            } else {
	                auto mp = address_to_socket_tcp.find(ip->daddr);
	                //printf("old socket = %d   %u   ", mp->first, mp->second);
	                struct sockaddr_in server;

	                server.sin_addr.s_addr = ip->daddr;
	                server.sin_family = AF_INET;
	                server.sin_port = htons(80);
	                if (sendto (s, pktb_data(pkBuff), pktb_len(pkBuff), 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
	                    perror("sendto failed");
	                }
	            }
	            
		    nfq_ip_set_checksum(ip);
		    nfq_tcp_compute_checksum_ipv4(tcp, ip);
		    free(cst);
		    free(recst);
		    printf("%d\n", pktb_len(pkBuff));
		    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
	    }
        }
        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        free(cst);
        free(recst);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

int main()
{
    struct nfq_handle * handler = nfq_open();
    if (handler == nullptr) {
         throw std::runtime_error("Cant open hfqueue handler.");
    }

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    if (queue == nullptr) {
         throw std::runtime_error("Cant open queue.");
    }

    int desc = nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff);
    
    if (desc < 0) {
         throw std::runtime_error("Cant set queue copy mode.");
    }

    int fd = nfq_fd(handler);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    std::array<char, 0x10000> buffer;
    for(;;) {
        int len = read(fd, buffer.data(), buffer.size());
        if (len < 0) {
        	throw std::runtime_error("Bad read");
        }
        nfq_handle_packet(handler, buffer.data(), len);
    }
    nfq_destroy_queue(queue);
    nfq_close(handler);
    return 0;
}
