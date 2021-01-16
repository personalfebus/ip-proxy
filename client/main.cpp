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

std::string secr = "thegreatsovietrevolution";
const byte* key = (const byte*) secr.data();
byte iv[CryptoPP::AES::BLOCKSIZE];

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

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    if (ip == nullptr) {
          throw std::runtime_error("Issue while ipv4 header parse");
    }
    //printf("iphdr=%d, total=%d, ", 4*(ip->ihl), ip->tot_len);
    //printf("sadress=%pI4\n", ip->saddr);
    //printf("dadress=%pI4\n", ip->daddr);
    //char source[16];
    //snprintf(source, 16, "%pI4", &ip->saddr); // Mind the &!
    //printf("%s\n", source);
    //ip->tot_len += 4;
    int desc = nfq_ip_set_transport_header(pkBuff, ip);
    if (desc < 0) {
         throw std::runtime_error("Cant set transport header.");
    }

    if(ip->protocol == IPPROTO_TCP)
    {
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
        cst->mem = ip->daddr;
        unsigned char t0 = cst->num[0];
        unsigned char t1 = cst->num[1];
        unsigned char t2 = cst->num[2];
        unsigned char t3 = cst->num[3];

        //printf("%d.%d.%d.%d\n", (int)t0, (int)t1, (int)t2, (int)t3);
        //134.0.117.159

        struct addr_cast *recst = (struct addr_cast*)malloc(sizeof(struct addr_cast));

        recst->num[0] = 134;
        recst->num[1] = 0;
        recst->num[2] = 117;
        recst->num[3] = 159;


        if (REDIRECT) {
            if (is_encrypted) {
                std::string plaintext;
                std::string ciphertext;
                for (unsigned int i = 0; i < payloadLen + 4; i++) {
                     if (i < payloadLen) {
                         plaintext.push_back(user_data[i]);
                     } else {
                        plaintext.push_back(recst->num[i -payloadLen]);
                    }
                }

                CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
                CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

                CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
                stfEncryptor.Put( reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
                stfEncryptor.MessageEnd();
                int cipher_resize = plaintext.size() - ciphertext.size();
                   
                struct pkt_buff *pkBuff2 = pktb_alloc(AF_INET, rawData, len + cipher_resize, 0x1000);
                if (pkBuff2 == nullptr) {
                    throw std::runtime_error("Issue while pktb allocate");
                }

                struct iphdr *ip2 = nfq_ip_get_hdr(pkBuff2);
                if (ip2 == nullptr) {
                    throw std::runtime_error("Issue while ipv4 header parse");
                }

                int desc2 = nfq_ip_set_transport_header(pkBuff2, ip2);
                if (desc2 < 0) {
                    throw std::runtime_error("Cant set transport header.");
                }

                struct tcphdr *tcp2 = nfq_tcp_get_hdr(pkBuff2);
                if (tcp2 == nullptr) {
                    throw std::runtime_error("Issue while tcp header.");
                }

                void *payload2 = nfq_tcp_get_payload(tcp2, pkBuff2);
                unsigned int payloadLen2 = nfq_tcp_get_payload_len(tcp2, pkBuff2);
                payloadLen2 -= 4 * tcp->th_off;

                if (payloadLen + cipher_resize != payloadLen2){
                    printf("%d -> %d\n", payloadLen, payloadLen2);
                }

                unsigned char *user_data2 = (unsigned char *)payload2;

                for (unsigned int i = 0; i < payloadLen2; i++) {
                    user_data2[i] = ciphertext[i];
                    //printf("%d.", user_data2[i]);
                }
                ip2->daddr = recst->mem;
                ip2->tot_len = htons(pktb_len(pkBuff2));

                nfq_ip_set_checksum(ip2);
                nfq_tcp_compute_checksum_ipv4(tcp2, ip2);
                free(cst);
                free(recst);
                printf("%d\n", pktb_len(pkBuff2));
                pktb_free(pkBuff);
                pktb_free(pkBuff2);
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff2), pktb_data(pkBuff2));
            } else {
                struct pkt_buff *pkBuff2 = pktb_alloc(AF_INET, rawData, len + 4, 0x1000);
                if (pkBuff2 == nullptr) {
                    throw std::runtime_error("Issue while pktb allocate");
                }

                struct iphdr *ip2 = nfq_ip_get_hdr(pkBuff2);
                if (ip2 == nullptr) {
                    throw std::runtime_error("Issue while ipv4 header parse");
                }
                ip2->tot_len += 4;

                int desc2 = nfq_ip_set_transport_header(pkBuff2, ip2);
                if (desc2 < 0) {
                    throw std::runtime_error("Cant set transport header.");
                }

                struct tcphdr *tcp2 = nfq_tcp_get_hdr(pkBuff2);
                if (tcp2 == nullptr) {
                    throw std::runtime_error("Issue while tcp header.");
                }

                void *payload2 = nfq_tcp_get_payload(tcp2, pkBuff2);
                unsigned int payloadLen2 = nfq_tcp_get_payload_len(tcp2, pkBuff2);
                payloadLen2 -= 4 * tcp->th_off;

                if (payloadLen + 4 != payloadLen2){
                    printf("%d -> %d\n", payloadLen, payloadLen2);
                }

                unsigned char *user_data2 = (unsigned char *)payload2;

                for (unsigned int i = payloadLen2 - 4; i < payloadLen2; i++) {
                    user_data2[i] = cst->num[i - payloadLen2 + 4];
                    printf("%d.", user_data2[i]);
                }
                ip2->daddr = recst->mem;
                ip2->tot_len = htons(pktb_len(pkBuff2));

                nfq_ip_set_checksum(ip2);
                nfq_tcp_compute_checksum_ipv4(tcp2, ip2);
                free(cst);
                free(recst);
                printf("%d\n", pktb_len(pkBuff2));
                pktb_free(pkBuff);
                pktb_free(pkBuff2);
                return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff2), pktb_data(pkBuff2));
		    }
        }
        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        free(cst);
        free(recst);
        pktb_free(pkBuff);
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
