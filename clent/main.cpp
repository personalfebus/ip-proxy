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

#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

int sock = socket(PF_PACKET, SOCK_RAW, 0);

struct addr_cast {
    union {
        unsigned char num[4];
        __be32 mem;
    };
};

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data");
    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up
    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");
    //printf("iphdr=%d, total=%d, ", 4*(ip->ihl), ip->tot_len);
    //printf("sadress=%pI4\n", ip->saddr);
    //printf("dadress=%pI4\n", ip->daddr);
    //char source[16];
    //snprintf(source, 16, "%pI4", &ip->saddr); // Mind the &!
    //printf("%s\n", source);
    //ip->tot_len += 4;
    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");

    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");

        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);

        payloadLen -= 4 * tcp->th_off;
        if (payloadLen <= 4) return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
        THROW_IF_TRUE(payload == nullptr, "Issue while payload.");
        unsigned char *user_data = (unsigned char *)payload;


        int jj = 0;

        bool REDIRECT = true;

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
            struct pkt_buff *pkBuff2 = pktb_alloc(AF_INET, rawData, len + 4, 0x1000);
            THROW_IF_TRUE(pkBuff2 == nullptr, "Issue while pktb allocate");
            struct iphdr *ip2 = nfq_ip_get_hdr(pkBuff2);
            ip2->tot_len += 4;
            THROW_IF_TRUE(ip2 == nullptr, "Issue while ipv4 header parse.");
            THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff2, ip2) < 0, "Can\'t set transport header.");
            struct tcphdr *tcp2 = nfq_tcp_get_hdr(pkBuff2);
            THROW_IF_TRUE(tcp2 == nullptr, "Issue while tcp header.");
            void *payload2 = nfq_tcp_get_payload(tcp2, pkBuff2);
            unsigned int payloadLen2 = nfq_tcp_get_payload_len(tcp2, pkBuff2);
            payloadLen2 -= 4 * tcp->th_off;

            if (payloadLen + 4 != payloadLen2){
                printf("%d -> %d\n", payloadLen, payloadLen2);
            }
//
//            for (unsigned int i = payloadLen2 - 1; i >= 4; i--) {
//                (static_cast<char *>(payload2))[i] = (static_cast<char *>(payload2))[i - 4];
//            }
//
//            for (unsigned int i = 0; i < 4; i++) {
//                (static_cast<char *>(payload2))[i] = cst->num[i];
//            }
//            for (unsigned int i = 0; i < 4; i++) {
//                printf("%d.", (static_cast<unsigned char *>(payload2))[i]);
//            }
//            printf("   ");

         
            for (unsigned int i = payloadLen - 4; i < payloadLen; i++) {
                user_data[i] = cst->num[i - payloadLen + 4];
                printf("%d.", user_data[i]);
            }
            ip->daddr = recst->mem;

            nfq_ip_set_checksum(ip2);
            nfq_tcp_compute_checksum_ipv4(tcp2, ip2);
            free(cst);
            free(recst);
            printf("%d\n", pktb_len(pkBuff));
            return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff2), pktb_data(pkBuff2));

            //nfq_ip_set_checksum(ip);
            //nfq_tcp_compute_checksum_ipv4(tcp, ip);
            //printf("iphdr=%d, total=%d, ", 4*(ip->ihl), ip->tot_len);
            //free(cst);
            //free(recst);
            return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
        }
        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        free(cst);
        free(recst);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    } else if (ip->protocol == IPPROTO_UDP) {

    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

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
