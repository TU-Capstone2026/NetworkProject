/* Linux: cc -std=c11 -O2 mail_capture.c -o mail_capture
 * macOS: cc -std=c11 -O2 mail_capture.c -lpcap -o mail_capture
 * Start before mail_demo. Ctrl-C stops the capture. */
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#else
#include <pcap/pcap.h>
#endif

static unsigned u16(const unsigned char *p) { return (unsigned)p[0]*256+p[1]; }
static uint32_t u32(const unsigned char *p) { return ((uint32_t)u16(p)<<16)|u16(p+2); }

static const char *service(unsigned port)
{
    switch (port) {
    case 465: case 587: case 25: case 2525: return "SMTP";
    case 995: case 110: case 11110: return "POP3";
    case 993: case 143: case 11430: return "IMAP";
    default: return NULL;
    }
}

/* Each directional stream has an independent TCP sequence space. */
#define WINDOW 8192
struct stream {
    uint64_t seen;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    uint32_t next, initial;
    bool tls;
    unsigned sport, dport;
    unsigned char pending[WINDOW], present[WINDOW];
    char line[2048];
    size_t length;
    bool clipped;
};
static struct stream streams[64];
static uint64_t serial;

static struct stream *lookup(const char *src, const char *dst, unsigned sp, unsigned dp,
                             uint32_t seq, bool syn)
{
    struct stream *slot=streams;
    for (size_t i=0; i<64; ++i) {
        struct stream *s=&streams[i];
        if (s->seen && !strcmp(s->src,src) && !strcmp(s->dst,dst) && s->sport==sp && s->dport==dp) {
            if (!syn || s->initial==seq) return s;
            slot=s;
            break;
        }
        if (s->seen<slot->seen) slot=s;
    }
    memset(slot,0,sizeof *slot);
    strcpy(slot->src,src); strcpy(slot->dst,dst); slot->sport=sp; slot->dport=dp;
    slot->initial=seq; slot->next=seq+syn;
    return slot;
}

static void payload(struct stream *s, uint32_t seq, const unsigned char *p,
                    size_t size, const char *name, const char *direction)
{
    for (size_t i=0; i<size; ++i, ++seq) {
        uint32_t gap=seq-s->next;
        if (gap>INT32_MAX) continue; /* Already delivered. */
        if (gap>=WINDOW) {
            printf("  [%s stream gap; resuming at seq=%" PRIu32 "]\n",name,seq);
            memset(s->present,0,sizeof s->present);
            s->length=0; s->clipped=false; s->next=seq;
        }
        unsigned index=seq%WINDOW;
        s->present[index]=1;
        s->pending[index]=p[i];
        while (s->present[s->next%WINDOW]) {
            index=s->next++%WINDOW;
            unsigned char c=s->pending[index];
            s->present[index]=0;
            /* The first handshake record begins with binary content type 22. */
            if ((s->sport==587 || s->dport==587) && !s->length && c==22) {
                s->tls=true;
                printf("  SMTP | TLS handshake record begins\n");
                return;
            }
            if (c=='\n') {
                s->line[s->length]=0;
                printf("  %s %s | %s%s\n",name,direction,s->line,s->clipped?" [...]":"");
                s->length=0; s->clipped=false;
            } else if (c!='\r') {
                if (s->length+1<sizeof s->line)
                    s->line[s->length++]=(c>=32 && c<=126)?(char)c:'.';
                else s->clipped=true;
            }
        }
    }
}

static void decode_tcp(const unsigned char *ip, size_t ih, const char *src, const char *dst, const unsigned char *tcp, size_t length)
{
    if (length<20) return;
    size_t th=(tcp[12]>>4)*4;
    if (th<20 || th>length) return;
    unsigned sp=u16(tcp), dp=u16(tcp+2);
    const char *name=service(sp);
    bool from_server=name!=NULL;
    if (!name) name=service(dp);
    if (!name) return;
    unsigned flags=tcp[13];
    size_t bytes=length-th;
    uint32_t seq=u32(tcp+4);
    printf("%s %s:%u -> %s:%u seq=%" PRIu32 " ack=%" PRIu32
           " flags=%s%s%s%s%s bytes=%zu\n",name,src,sp,dst,dp,seq,u32(tcp+8),
           flags&2?" SYN":"",flags&16?" ACK":"",flags&8?" PSH":"",
           flags&1?" FIN":"",flags&4?" RST":"",bytes);
    printf("HEADERS ");
    for (size_t i=0; i<ih; ++i) printf("%02x",ip[i]);
    putchar(' ');
    for (size_t i=0; i<th; ++i) printf("%02x",tcp[i]);
    putchar('\n');
    bool syn=(flags&2)!=0;
    if (bytes || syn) {
        struct stream *s=lookup(src,dst,sp,dp,seq,syn);
        s->seen=++serial;
        unsigned port=from_server ? sp : dp;
        if (port==465 || port==993 || port==995 || (port==587 && s->tls)) {
            if (bytes) {
                const unsigned char *record=tcp+th;
                const char *label="TLS transport";
                if (bytes>=6 && record[0]==22 && record[1]==3 && record[2]<=4) {
                    if (record[5]==1) label="TLS ClientHello";
                    else if (record[5]==2) label="TLS ServerHello";
                }
                printf("  %s | %s (%zu B)\n",name,label,bytes);
            }
            return;
        }
        payload(s,seq+syn,tcp+th,bytes,name,from_server?"S>C":"C>S");
    }
}

static void ipv4(const unsigned char *ip, size_t n)
{
    if (n<20 || ip[0]>>4!=4 || ip[9]!=6 || (u16(ip+6)&0x3fff)) return;
    size_t ih=(ip[0]&15)*4, total=u16(ip+2);
    if (ih<20 || total>n || total<ih) return;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,ip+12,src,sizeof src);
    inet_ntop(AF_INET,ip+16,dst,sizeof dst);
    decode_tcp(ip,ih,src,dst,ip+ih,total-ih);
}

static void ipv6(const unsigned char *ip, size_t n)
{
    if (n<40 || ip[0]>>4!=6 || ip[6]!=6 || u16(ip+4)>n-40) return;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,ip+8,src,sizeof src);
    inet_ntop(AF_INET6,ip+24,dst,sizeof dst);
    decode_tcp(ip,40,src,dst,ip+40,u16(ip+4));
}

static void ethernet(const unsigned char *p,size_t n)
{
    if (n<14) return;
    unsigned type=u16(p+12);
    size_t offset=14;
    while (type==0x8100 || type==0x88a8) {
        if (n-offset<4) return;
        type=u16(p+offset+2);
        offset+=4;
    }
    if (type==0x800) ipv4(p+offset,n-offset);
    else if (type==0x86dd) ipv6(p+offset,n-offset);
}

int main(int argc,char **argv)
{
    if (argc!=2) { fprintf(stderr,"Usage: %s INTERFACE\n",argv[0]); return 1; }
    setvbuf(stdout,NULL,_IOLBF,0);
#ifdef __linux__
    unsigned index=if_nametoindex(argv[1]);
    if (!index) { perror("interface"); return 1; }
    int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (fd<0) { perror("packet socket"); return 1; }
    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),
                             .sll_ifindex=(int)index};
    if (bind(fd,(struct sockaddr *)&addr,sizeof addr)<0) { perror("bind"); return 1; }
    printf("Capturing mail on %s\n",argv[1]);
    unsigned char frame[65536+64];
    for (;;) {
        socklen_t length=sizeof addr;
        ssize_t n=recvfrom(fd,frame,sizeof frame,0,(struct sockaddr *)&addr,&length);
        if (n<0) { perror("recvfrom"); return 1; }
        if (addr.sll_hatype==ARPHRD_LOOPBACK && addr.sll_pkttype==PACKET_OUTGOING) continue;
        if (addr.sll_hatype==ARPHRD_LOOPBACK || addr.sll_hatype==ARPHRD_ETHER)
            ethernet(frame,(size_t)n);
    }
#else
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *cap=pcap_open_live(argv[1],262144,0,100,error);
    if (!cap) { fprintf(stderr,"%s\n",error); return 1; }
    int link=pcap_datalink(cap);
    if (link!=DLT_NULL && link!=DLT_EN10MB) {
        fprintf(stderr,"Unsupported link type %d\n",link); pcap_close(cap); return 1;
    }
    printf("Capturing mail on %s\n",argv[1]);
    struct pcap_pkthdr *header;
    const unsigned char *p;
    int status;
    while ((status=pcap_next_ex(cap,&header,&p))>=0) {
        if (!status) continue;
        if (link==DLT_EN10MB) ethernet(p,header->caplen);
        else if (header->caplen>=4) {
            uint32_t family;
            memcpy(&family,p,4);
            if (family==AF_INET) ipv4(p+4,header->caplen-4);
            else if (family==AF_INET6) ipv6(p+4,header->caplen-4);
        }
    }
    if (status==-1) fprintf(stderr,"%s\n",pcap_geterr(cap));
    pcap_close(cap);
    return status==-1;
#endif
}
