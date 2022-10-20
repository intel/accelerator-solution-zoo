#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>

#include "virtqueue.h"

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "cpu.h"
#include "netlib.h"
#include "debug.h"

#define MAX_FLOW_NUM  (10000)

#define RCVBUF_SIZE 1500

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#ifndef MAX_CPUS
#define MAX_CPUS		16
#endif
/*----------------------------------------------------------------------------*/
struct server_vars
{
	int recv_len;
	int request_len;
	long int total_read, total_sent;
	uint8_t done;
	uint8_t rspheader_sent;
	uint8_t keep_alive;
};
/*----------------------------------------------------------------------------*/
struct thread_context
{
	mctx_t mctx;
	int ep;
	struct server_vars *svars;
};
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static pthread_t app_thread[MAX_CPUS] = { 0 };
static int done[MAX_CPUS] = { 0 };
static char *conf_file = NULL;
static int backlog = -1;
static char *peer_addr = NULL;
static int peer_port = 7777;
static int ping_size = 4096;
static int read_cpu = 5;
static int virtq_cpu = 6;
static int write_cpu = 7; //write application run on cpu 7
extern int use_dsa;
static int nb_bufs = 128; //data chunk number
static int sleep_us = 0;
static uint64_t buf_size = 1048576; //data chunk size
extern int sndbuf_size_auto_match;
/*----------------------------------------------------------------------------*/
void CleanServerVariable(struct server_vars *sv)
{
	sv->recv_len = 0;
	sv->request_len = 0;
	sv->total_read = 0;
	sv->total_sent = 0;
	sv->done = 0;
	sv->rspheader_sent = 0;
	sv->keep_alive = 0;
}
/*----------------------------------------------------------------------------*/
void CloseConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
}
/*----------------------------------------------------------------------------*/
static int read_poll(struct thread_context *ctx, int sockid, void *buf, int len)
{
	while (len > 0)
	{
		int rcv = mtcp_read(ctx->mctx, sockid, buf, len);
		if (rcv < 0)
		{
			if (errno == EAGAIN)
				continue;
			printf("read() failed: %d (%s).\n", errno, strerror(errno));
			return -errno;
		}
		len -= rcv;
		buf += rcv;
	}
	return 0;
}
/*----------------------------------------------------------------------------*/
static int write_poll(struct thread_context *ctx, int sockid, void *buf, int len)
{
	while (len > 0)
	{
		int sent = mtcp_write(ctx->mctx, sockid, buf, len);
		if (sent < 0)
		{
			if (errno == EAGAIN)
				continue;
			printf("write() failed: %d (%s).\n", errno, strerror(errno));
			return -errno;
		}
		len -= sent;
		buf += sent;
	}
	return 0;
}
/*----------------------------------------------------------------------------*/
static int HandleReadEvent(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	char buf[RCVBUF_SIZE];
	int rd;
	rd = mtcp_read(ctx->mctx, sockid, buf, RCVBUF_SIZE);
	if(rd < 0) {
		//recv failed
		//printf("application recv failed, ret:%d\n", rd);
		return rd;
	}
/*
	char* p_buf = NULL;
        uint16_t idx = 0;
	int len = 0;
        struct virtqueue* vq_rx = get_virtq_rx(ctx->mctx);

        if(vhost_get_req(&p_buf, &len, &idx, vq_rx)){
                return -1;
        }

	//if(p_buf != NULL) printf("application recv pkt from virtio-queue, buff-content:%s\n", p_buf);
        vhost_virtqueue_done(idx, vq_rx);
*/
	//printf("application recv len: %d, buff-content:%s\n", rd, buf);
	//rd = mtcp_write(ctx->mctx, sockid, buf, rd);
	return 0;
}

/*----------------------------------------------------------------------------*/
uint64_t recv_cnt = 0;
uint write_cnt = 0;
uint fail_cnt = 0;
struct timeval tv1, tv2;
char *buf = NULL;
#define fifo_depth 2
int once = 0;
unsigned char *sbuff, *dbuff;
char *sbf_arr[65536];

struct iovec *chunks;

static int HandleWriteEvent(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
        int rd;
	static int i;
        if (once == 0) {
			for(i = 0;i < nb_bufs; i++) {
                                sbf_arr[i] = valloc(buf_size);

                                if(sbf_arr[i] == NULL) {
                                        printf("alloc memory buff failed!\n");
                                        return -1;
                                }
				memset(sbf_arr[i], 0x99, buf_size);
			}
                        once = 1 ;
			i = 0;
        }


        if(write_cnt == 0) {
                gettimeofday(&tv1, NULL);
        }
	//discrete write data
	i += 2;
	if (i > nb_bufs-1) {
		i -= (nb_bufs-1);
	}

	if(use_dsa == 1) {
		//copy data to tcp send buffer use dsa
       		rd = mtcp_write_async(ctx->mctx, sockid, sbf_arr[i], buf_size);
	} else {
		//copy data to tcp send buffer use cpu
		rd = mtcp_write(ctx->mctx, sockid, sbf_arr[i], buf_size);
	}

	write_cnt++;
        if(rd < 0) {
                fail_cnt++;
		if(sleep_us != 0) {
                	usleep(sleep_us);
		}
        }
        gettimeofday(&tv2, NULL);
        if(tv2.tv_sec - tv1.tv_sec > 1){
                printf("write  cnt %d\n", write_cnt);
                printf("failed cnt %d\n", fail_cnt);
                tv1.tv_sec = tv2.tv_sec;
                tv1.tv_usec = tv2.tv_usec;
                write_cnt = 0;
                fail_cnt = 0;
                }

        return rd;
}

/*----------------------------------------------------------------------------*/
int AcceptConnection(struct thread_context *ctx, int listener)
{
	mctx_t mctx = ctx->mctx;
	struct server_vars *sv;
	struct mtcp_epoll_event ev;
	int c;

	c = mtcp_accept(mctx, listener, NULL, NULL);

	if (c >= 0)
	{
		if (c >= MAX_FLOW_NUM)
		{
			TRACE_ERROR("Invalid socket id %d.\n", c);
			return -1;
		}

		sv = &ctx->svars[c];
		CleanServerVariable(sv);
		TRACE_APP("New connection %d accepted.\n", c);
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(ctx->mctx, c);
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
		TRACE_APP("Socket %d registered.\n", c);
	}
	else
	{
		if (errno != EAGAIN)
		{
			TRACE_ERROR("mtcp_accept() error %s\n", strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
struct thread_context *InitializeServerThread(int core)
{
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx)
	{
		TRACE_ERROR("Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx)
	{
		TRACE_ERROR("Failed to create mtcp context!\n");
		free(ctx);
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0)
	{
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

	/* allocate memory for server variables */
	ctx->svars = (struct server_vars *)calloc(MAX_FLOW_NUM, sizeof(struct server_vars));
	if (!ctx->svars)
	{
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create server_vars struct!\n");
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
int CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	struct mtcp_epoll_event ev;
	struct sockaddr_in saddr;
	int ret;

	/* create socket and set it as nonblocking */
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
	{
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}

	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0)
	{
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(peer_port);
	ret = mtcp_bind(ctx->mctx, listener, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listen (backlog: can be configured) */
	ret = mtcp_listen(ctx->mctx, listener, backlog);
	if (ret < 0)
	{
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}

	/* wait for incoming accept events */
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	return listener;
}
/*----------------------------------------------------------------------------*/
static inline int CreateConnection(struct thread_context *ctx, char *peer_addr, int peer_port)
{
	mctx_t mctx = ctx->mctx;
	struct sockaddr_in addr;
	int sockid;
	int ret;
	struct mtcp_epoll_event ev;

	sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0)
	{
		TRACE_INFO("Failed to create socket!\n");
		return -1;
	}

	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0)
	{
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(peer_addr);
	addr.sin_port = htons(peer_port);

	ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		if (errno != EINPROGRESS)
		{
			perror("mtcp_connect");
			mtcp_close(mctx, sockid);
			return -1;
		}
	}

	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

	{
		struct mtcp_epoll_event events[8];
		int found = 0;
		while (!found)
		{
			int i, nev = mtcp_epoll_wait(mctx, ctx->ep, events, 8, -1);
			for (i = 0; i < nev; i++)
			{
				if (events[i].data.sockid == sockid && (events[i].events & (MTCP_EPOLLOUT | MTCP_EPOLLERR)))
				{
					if (events[i].events & MTCP_EPOLLERR)
					{
						int err;
						socklen_t len = sizeof(err);
						mtcp_getsockopt(mctx, events[i].data.sockid, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
						printf("Error on socket %d: %d (%s)\n", events[i].data.sockid, err, strerror(err));
					}
					found = 1;
					break;
				}
			}
		}
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = sockid;
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
	}

	return sockid;
}
/*----------------------------------------------------------------------------*/
void *RunClientThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	int sockfd = 0;
	int ret;
	uint64_t sum_us = 0, count_us = 0;
	char* buf = malloc(ping_size);

	if (!buf)
	{
		TRACE_ERROR("Failed to allocate %d bytes.\n", ping_size);
		return NULL;
	}

	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx)
	{
		TRACE_ERROR("Failed to initialize client thread.\n");
		free(buf);
		return NULL;
	}
	mctx = ctx->mctx;

	sockfd = CreateConnection(ctx, peer_addr, peer_port);
	if (sockfd < 0)
	{
		goto end;
	}

	while (!done[core])
	{
		struct timespec start, end;
		clock_gettime(CLOCK_REALTIME, &start);
		memset(buf, 0xAA, ping_size);
		ret = write_poll(ctx, sockfd, buf, ping_size);
		if (ret < 0)
		{
			printf("write() failed - connection closed by server\n");
			break;
		}
/*		printf("Waiting\n");
		{
			struct mtcp_epoll_event events[8];
			int found = 0;
			while (!found)
			{
				int i, nev = mtcp_epoll_wait(mctx, ctx->ep, events, 8, -1);
				for (i = 0; i < nev; i++)
				{
					if (events[i].data.sockid == sockfd)
					{
						found = 1;
						break;
					}
				}
			}
		}*/
		ret = read_poll(ctx, sockfd, buf, ping_size);
		if (ret < 0)
		{
			printf("read() failed - connection closed by server\n");
			break;
		}
		clock_gettime(CLOCK_REALTIME, &end);
		sum_us += (end.tv_nsec - start.tv_nsec)/1000 + (end.tv_sec - start.tv_sec)*1000000;
		count_us++;
		printf("Done %lu us\n", (end.tv_nsec - start.tv_nsec)/1000 + (end.tv_sec - start.tv_sec)*1000000);
	}
	printf("Done\n");

end:
	printf("%lu messages received, %lu us avg ping-pong\n", count_us, sum_us/(count_us == 0 ? 1 : count_us));

	/* destroy mtcp context: this will kill the mtcp thread */
	if (sockfd)
		mtcp_close(ctx->mctx, sockfd);
	if (ctx)
		mtcp_destroy_context(mctx);
	if (buf)
		free(buf);
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
int g_listener = 0;
void *read_thread_func(void *arg)
{
	struct thread_context *ctx = (struct thread_context *)arg;
	uint64_t app_rcv_num = 0;
	struct timeval tv_cur, tv_prv;
	
	mtcp_core_affinitize(read_cpu);
	
	gettimeofday(&tv_prv, NULL);
	while (!done[read_cpu])
        {
		int ret = 0;

                ret = HandleReadEvent(ctx, g_listener, NULL);
		if(ret < 0) {
			continue;
		}

		app_rcv_num++;
		gettimeofday(&tv_cur, NULL);

		if(tv_cur.tv_sec - tv_prv.tv_sec > 3){
			float sec_passed = tv_cur.tv_sec - tv_prv.tv_sec + ((float)(tv_cur.tv_usec - tv_prv.tv_usec))/1000000;
			float pps = app_rcv_num / sec_passed;
			printf("mtcp_read PPS:%.2f \n", pps);
			//reload time stamps
                	tv_prv.tv_sec = tv_cur.tv_sec;
			tv_prv.tv_usec = tv_cur.tv_usec;
			app_rcv_num = 0;
        	}
        }

	return NULL;
}

void *write_thread_func(void *arg)
{
	struct thread_context *ctx = (struct thread_context *)arg;
	
	mtcp_core_affinitize(write_cpu);
	
	while (!done[write_cpu])
        {

		HandleWriteEvent(ctx, g_listener, NULL);
        }

	return NULL;
}

void *vq_thread_func(void *arg)
{
	struct thread_context *ctx = (struct thread_context *)arg;
	uint32_t app_rcv_num = 0;
        struct timeval tv_cur, tv_prv;
	struct virtqueue* vq_rx = NULL;

	mtcp_core_affinitize(virtq_cpu);

	vq_rx = get_virtq_rx(ctx->mctx);
	if(vq_rx == NULL) {
		printf("Failed to get rx virtqueue\n");
		return NULL;
        }

	gettimeofday(&tv_prv, NULL);
	while (!done[virtq_cpu]){
		char* p_buf = NULL;
		uint16_t idx = 0;
		int len = 0;
		
		if(vhost_get_req(&p_buf, &len, &idx, vq_rx)){
			continue;
		}

		//if(p_buf != NULL) printf("application recv pkt from virtio-queue, buff-content:%s\n", p_buf);
		vhost_virtqueue_done(idx, vq_rx);	
		if(p_buf != NULL) app_rcv_num++;
                gettimeofday(&tv_cur, NULL);

                if(tv_cur.tv_sec - tv_prv.tv_sec > 3){
                        float sec_passed = tv_cur.tv_sec - tv_prv.tv_sec + ((float)(tv_cur.tv_usec - tv_prv.tv_usec))/1000000;
                        float pps = app_rcv_num / sec_passed;
                        printf("application recv PPS:%.2f \n", pps);
                        //reload time stamps
                        tv_prv.tv_sec = tv_cur.tv_sec;
                        tv_prv.tv_usec = tv_cur.tv_usec;
                        app_rcv_num = 0;
                }
	}

	return NULL;
}

void *RunServerThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	int listener;
	struct mtcp_epoll_event *events;
	
	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx)
	{
		TRACE_ERROR("Failed to initialize server thread.\n");
		return NULL;
	}
	mctx = ctx->mctx;

	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events)
	{
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	listener = CreateListeningSocket(ctx);
	if (listener < 0)
	{
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}

	AcceptConnection(ctx, listener);
	g_listener = listener;
	sleep(3);

	//pthread_create(&app_thread[read_cpu], NULL, read_thread_func, ctx);
	pthread_create(&app_thread[write_cpu], NULL, write_thread_func, ctx);
	//pthread_create(&app_thread[virtq_cpu], NULL, vq_thread_func, ctx);

	while(!done[core])
	{
		sleep(3);
	}
	//pthread_join(app_thread[read_cpu], NULL);
	//pthread_join(app_thread[virtq_cpu], NULL);
	//pthread_join(app_thread[write_cpu], NULL);
	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(mctx);
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void SignalHandler(int signum)
{
	int i;
	for (i = 0; i < core_limit; i++)
	{
		if (app_thread[i] == pthread_self())
		{
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		}
		else if (app_thread[i])
		{
			if (!done[i])
			{
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
static void printHelp(const char *prog_name)
{
	TRACE_CONFIG("%s -f <mtcp_conf_file> [-c <peer_ip>] [-p <port>] [-s <ping_size>] [-h]\n", prog_name);
	exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
static int
parse_blen(uint64_t *blen, char *str)
{
	char c;
	uint32_t m;

	*blen = 0;
	c = toupper(str[strlen(str) - 1]);

	switch (c) {
	case 'K':
		m = 1024;
		break;

	case 'M':
		m = 1024 * 1024;
		break;

	case 'G':
		m = 1024 * 1024 * 1024;
		break;

	default:
		m = 1;
	}

	if (m != 1)
		str[strlen(str) - 1] = '\0';

	*blen = strtoul(str, NULL, 0);
	*blen *= m;

	return 0;
}

/*----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	int ret;
	int cores[MAX_CPUS];
	int process_cpu = 0;
	int i, o;

	struct mtcp_conf mcfg;

	num_cores = GetNumCPUs();
	core_limit = num_cores;

	while (-1 != (o = getopt(argc, argv, "u:l:n:f:c:p:s:dh")))
	{
		switch (o)
		{
		case 'u':
			sleep_us = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			if (parse_blen(&buf_size, optarg) != 0)
				return -EINVAL;
			break;
		case 'n':
			nb_bufs = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 'c':
			peer_addr = optarg;
			break;
		case 'p':
			peer_port = atoi(optarg);
			break;
		case 's':
			ping_size = atoi(optarg);
			break;
		case 'd': //use dsa
			use_dsa = 1;
			break;
		case 'h':
			printHelp(argv[0]);
			break;
		}
	}
	// printf("blen = %ld, nb_bufs = %d, use dsa = %d \n", blen, nb_bufs, use_dsa);
	if (peer_addr == NULL)
	{
		TRACE_CONFIG("Server mode\n");
	}

	/* initialize mtcp */
	if (conf_file == NULL)
	{
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}
	sndbuf_size_auto_match = buf_size;
	ret = mtcp_init(conf_file);
	if (ret)
	{
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency)
	{
		TRACE_CONFIG("backlog can not be set larger than CONFIG.max_concurrency\n");
		return FALSE;
	}

	/* if backlog is not specified, set it to 4K */
	if (backlog == -1)
	{
		backlog = 4096;
	}

	core_limit = mcfg.num_cores;
	if( core_limit > MAX_CPUS - 1) {
		core_limit = MAX_CPUS - 1;
	}
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	TRACE_INFO("Application initialization finished.\n");

	for (i = process_cpu; i < core_limit; i++)
	{
		cores[i] = i;
		if (pthread_create(&app_thread[i], NULL, peer_addr == NULL ? RunServerThread : RunClientThread, (void *)&cores[i]))
		{
			perror("pthread_create");
			TRACE_CONFIG("Failed to create server thread.\n");
			exit(EXIT_FAILURE);
		}
		else
		{
			// Run on one core
			process_cpu = i;
			break;
		}
	}

	pthread_join(app_thread[process_cpu], NULL);

	mtcp_destroy();
	return 0;
}
