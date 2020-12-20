#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data");

    struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up
//0x9f750086I4
    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");
    //printf("sadress=%pI4\n", ip->saddr);
    //printf("dadress=%pI4\n", ip->daddr);
    char source[16];
    snprintf(source, 16, "%pI4", &ip->saddr); // Mind the &!
    //printf("%s\n", source);

    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");

    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");

        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        payloadLen -= 4 * tcp->th_off;

        THROW_IF_TRUE(payload == nullptr, "Issue while payload.");
        unsigned char *user_data = (unsigned char *)payload;
//        int jj = 0;
//        for (unsigned char *it = user_data; jj < payloadLen; ++it) {
//            char c = *(char *)it;
//
//            if (c == '\0')
//                break;
//
//            printf("%c", c);
//            jj++;
//            if (jj == payloadLen) printf("\n");
//        }
        for (unsigned int i = 0; i < payloadLen / 2; ++i) {
            char tmp = (static_cast<char *>(payload))[i];
            //infile << (static_cast<char *>(payload));
            //printf("%c", tmp);
            //(static_cast<char *>(payload))[i] = (static_cast<char *>(payload))[payloadLen - 1 - i];
            //(static_cast<char *>(payload))[payloadLen - 1 - i] = tmp;
        }
        //printf("\n");
//0x9f750086I4
//myadr 0x5634a2d3e19c
//servadr 0x5589e4df5240I
//servadr 0x5589e4df31a0I
        //__be32 test = ntohl(0x5589e4df31a0);
        //ip->daddr = test;
        //nfq_ip_set_checksum(ip);
        struct addr_cast {
            union {
                unsigned char num[4];
                __be32 mem;
            };
        };
        struct addr_cast *cst = (struct addr_cast*)malloc(sizeof(struct addr_cast));
        cst->mem = ip->saddr;
        unsigned char t0 = cst->num[0];
        unsigned char t1 = cst->num[1];
        unsigned char t2 = cst->num[2];
        unsigned char t3 = cst->num[3];
        //printf("%d.%d.%d.%d\n", (int)t0, (int)t1, (int)t2, (int)t3);
        free(cst);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    } else if (ip->protocol == IPPROTO_UDP) {

    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}


//include_directories(libnetfilter_queue-1.0.5/include)
int main()
{
    struct nfq_handle * handler = nfq_open();
    THROW_IF_TRUE(handler == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler); ); // Don’t forget to clean up

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue); ); // Do not forget to clean up

    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    for(;;)
    {
        int len = read(fd, buffer.data(), buffer.size());
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }
    return 0;
}
