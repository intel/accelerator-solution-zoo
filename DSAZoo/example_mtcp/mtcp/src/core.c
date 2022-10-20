#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/time.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <signal.h>
#include <assert.h>
#include <sched.h>

#include "cpu.h"
#include "ps.h"
#include "eth_in.h"
#include "fhash.h"
#include "tcp_send_buffer.h"
#include "tcp_ring_buffer.h"
#include "socket.h"
#include "eth_out.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "mtcp_api.h"
#include "eventpoll.h"
#include "logger.h"
#include "config.h"
#include "arp.h"
#include "ip_out.h"
#include "timer.h"
#include "debug.h"
#if USE_CCP
#include "ccp.h"
#include "libccp/ccp.h"
#endif

#ifndef DISABLE_DPDK
/* for launching rte thread */
#include <rte_launch.h>
#include <rte_lcore.h>
#endif

#ifdef ENABLE_ONVM
#include "onvm_nflib.h"
#endif

#define PS_CHUNK_SIZE 64
#define RX_THRESH (PS_CHUNK_SIZE * 0.8)

#define ROUND_STAT FALSE
#define EVENT_STAT FALSE
#define TESTING FALSE

#define LOG_FILE_NAME "log"
#define MAX_FILE_NAME 1024

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define PER_STREAM_SLICE 0.1		// in ms
#define PER_STREAM_TCHECK 1			// in ms
#define PS_SELECT_TIMEOUT 100		// in us 

#define GBPS(bytes) (bytes * 8.0 / (1000 * 1000 * 1000))

extern mctx_t mctx_tmp;
extern tcp_stream *cur_stream_tmp;
extern struct tcp_send_vars *sndvar_tmp;
extern size_t len_tmp;
extern size_t tail_off_tmp;
extern bool dsa_running;
/*----------------------------------------------------------------------------*/
/* handlers for threads */
struct mtcp_thread_context *g_pctx[MAX_CPUS] = {0};
struct log_thread_context *g_logctx[MAX_CPUS] = {0};
/*----------------------------------------------------------------------------*/
static pthread_t g_thread[MAX_CPUS] = {0};
#if defined (PKTDUMP) || (DBGMSG) || (DBGFUNC) ||		\
	(STREAM) || (STATE) || (STAT) || (APP) || (EPOLL)	\
	|| (DUMP_STREAM)
static pthread_t log_thread[MAX_CPUS]  = {0};
#endif
#if USE_CCP
static pthread_t ccp_run_thread = 0;
static pthread_t ccp_recv_thread[MAX_CPUS] = {0};
#endif
/*----------------------------------------------------------------------------*/
static sem_t g_init_sem[MAX_CPUS];
static int running[MAX_CPUS] = {0};
/*----------------------------------------------------------------------------*/
mtcp_sighandler_t app_signal_handler;
static int sigint_cnt[MAX_CPUS] = {0};
static struct timespec sigint_ts[MAX_CPUS];
/*----------------------------------------------------------------------------*/
static int mtcp_master = -1;
void 
mtcp_free_context(mctx_t mctx);
/*----------------------------------------------------------------------------*/
void
HandleSignal(int signal)
{
	int i = 0;

	if (signal == SIGINT) {
		int core;
		struct timespec cur_ts;

#ifdef ENABLE_ONVM
		if (current_iomodule_func == &onvm_module_func)
			onvm_nflib_stop(CONFIG.nf_local_ctx);
#endif
		core = sched_getcpu();
		clock_gettime(CLOCK_REALTIME, &cur_ts);

		if (CONFIG.multi_process) {
			for (i = 0; i < num_cpus; i++)
				if (running[i] == TRUE)
					g_pctx[i]->exit = TRUE;
		} else {
			if (sigint_cnt[core] > 0 && cur_ts.tv_sec > sigint_ts[core].tv_sec) {
				for (i = 0; i < num_cpus; i++) {
					if (running[i]) {
						g_pctx[i]->exit = TRUE;
					}
				}
			} else {
				for (i = 0; i < num_cpus; i++) {
					if (running[i])
						g_pctx[i]->interrupt = TRUE;
				}
				if (!app_signal_handler) {
					for (i = 0; i < num_cpus; i++) {
						if (running[i]) {
							g_pctx[i]->exit = TRUE;
						}
					}
				}
			}
			sigint_cnt[core]++;
			clock_gettime(CLOCK_REALTIME, &sigint_ts[core]);
		}
	}

	if (signal != SIGUSR1) {
		if (app_signal_handler) {
			app_signal_handler(signal);
		}
	}
}
/*----------------------------------------------------------------------------*/
static int 
AttachDevice(struct mtcp_thread_context* ctx)
{
	int working = -1;
	mtcp_manager_t mtcp = ctx->mtcp_manager;

	working = mtcp->iom->link_devices(ctx);

	return working;
}
/*----------------------------------------------------------------------------*/
#ifdef NETSTAT
static inline void 
InitStatCounter(struct stat_counter *counter)
{
	counter->cnt = 0;
	counter->sum = 0;
	counter->max = 0;
	counter->min = 0;
}
/*----------------------------------------------------------------------------*/
static inline void 
UpdateStatCounter(struct stat_counter *counter, int64_t value)
{
	counter->cnt++;
	counter->sum += value;
	if (value > counter->max)
		counter->max = value;
	if (counter->min == 0 || value < counter->min)
		counter->min = value;
}
/*----------------------------------------------------------------------------*/
static inline uint64_t 
GetAverageStat(struct stat_counter *counter)
{
	return counter->cnt ? (counter->sum / counter->cnt) : 0;
}
/*----------------------------------------------------------------------------*/
static inline int64_t 
TimeDiffUs(struct timeval *t2, struct timeval *t1)
{
	return (t2->tv_sec - t1->tv_sec) * 1000000 + 
			(int64_t)(t2->tv_usec - t1->tv_usec);
}
/*----------------------------------------------------------------------------*/
static inline void 
PrintThreadNetworkStats(mtcp_manager_t mtcp, struct net_stat *ns)
{
	int i;

	for (i = 0; i < CONFIG.eths_num; i++) {
		ns->rx_packets[i] = mtcp->nstat.rx_packets[i] - mtcp->p_nstat.rx_packets[i];
		ns->rx_errors[i] = mtcp->nstat.rx_errors[i] - mtcp->p_nstat.rx_errors[i];
		ns->rx_bytes[i] = mtcp->nstat.rx_bytes[i] - mtcp->p_nstat.rx_bytes[i];
		ns->tx_packets[i] = mtcp->nstat.tx_packets[i] - mtcp->p_nstat.tx_packets[i];
		ns->tx_drops[i] = mtcp->nstat.tx_drops[i] - mtcp->p_nstat.tx_drops[i];
		ns->tx_bytes[i] = mtcp->nstat.tx_bytes[i] - mtcp->p_nstat.tx_bytes[i];
#if NETSTAT_PERTHREAD
		if (CONFIG.eths[i].stat_print) {
			fprintf(stderr, "[CPU%2d] %s flows: %6u, "
					"RX: %7ld(pps) (err: %5ld), %5.2lf(Gbps), "
					"TX: %7ld(pps), %5.2lf(Gbps)\n", 
					mtcp->ctx->cpu, CONFIG.eths[i].dev_name, mtcp->flow_cnt, 
					ns->rx_packets[i], ns->rx_errors[i], GBPS(ns->rx_bytes[i]), 
				ns->tx_packets[i], GBPS(ns->tx_bytes[i]));
		}
#endif
	}
#ifdef ENABLELRO
	ns->rx_gdptbytes = mtcp->nstat.rx_gdptbytes - mtcp->p_nstat.rx_gdptbytes;
	ns->tx_gdptbytes = mtcp->nstat.tx_gdptbytes - mtcp->p_nstat.tx_gdptbytes;
#endif
	mtcp->p_nstat = mtcp->nstat;

}
/*----------------------------------------------------------------------------*/
#if ROUND_STAT
static inline void 
PrintThreadRoundStats(mtcp_manager_t mtcp, struct run_stat *rs)
{
#define ROUND_DIV (1000)
	rs->rounds = mtcp->runstat.rounds - mtcp->p_runstat.rounds;
	rs->rounds_rx = mtcp->runstat.rounds_rx - mtcp->p_runstat.rounds_rx;
	rs->rounds_rx_try = mtcp->runstat.rounds_rx_try - mtcp->p_runstat.rounds_rx_try;
	rs->rounds_tx = mtcp->runstat.rounds_tx - mtcp->p_runstat.rounds_tx;
	rs->rounds_tx_try = mtcp->runstat.rounds_tx_try - mtcp->p_runstat.rounds_tx_try;
	rs->rounds_select = mtcp->runstat.rounds_select - mtcp->p_runstat.rounds_select;
	rs->rounds_select_rx = mtcp->runstat.rounds_select_rx - mtcp->p_runstat.rounds_select_rx;
	rs->rounds_select_tx = mtcp->runstat.rounds_select_tx - mtcp->p_runstat.rounds_select_tx;
	rs->rounds_select_intr = mtcp->runstat.rounds_select_intr - mtcp->p_runstat.rounds_select_intr;
	rs->rounds_twcheck = mtcp->runstat.rounds_twcheck - mtcp->p_runstat.rounds_twcheck;
	mtcp->p_runstat = mtcp->runstat;
#if NETSTAT_PERTHREAD
	fprintf(stderr, "[CPU%2d] Rounds: %4ldK, "
			"rx: %3ldK (try: %4ldK), tx: %3ldK (try: %4ldK), "
			"ps_select: %4ld (rx: %4ld, tx: %4ld, intr: %3ld)\n", 
			mtcp->ctx->cpu, rs->rounds / ROUND_DIV, 
			rs->rounds_rx / ROUND_DIV, rs->rounds_rx_try / ROUND_DIV, 
			rs->rounds_tx / ROUND_DIV, rs->rounds_tx_try / ROUND_DIV, 
			rs->rounds_select, 
			rs->rounds_select_rx, rs->rounds_select_tx, rs->rounds_select_intr);
#endif
}
#endif /* ROUND_STAT */
/*----------------------------------------------------------------------------*/
#endif /* NETSTAT */
/*----------------------------------------------------------------------------*/
#if EVENT_STAT
static inline void 
PrintEventStat(int core, struct mtcp_epoll_stat *stat)
{
	fprintf(stderr, "[CPU%2d] calls: %lu, waits: %lu, wakes: %lu, "
			"issued: %lu, registered: %lu, invalidated: %lu, handled: %lu\n", 
			core, stat->calls, stat->waits, stat->wakes, 
			stat->issued, stat->registered, stat->invalidated, stat->handled);
	memset(stat, 0, sizeof(struct mtcp_epoll_stat));
}
#endif /* EVENT_STAT */
/*----------------------------------------------------------------------------*/
#ifdef NETSTAT
static inline void
PrintNetworkStats(mtcp_manager_t mtcp, uint32_t cur_ts)
{
#define TIMEOUT 1
	int i;
	struct net_stat ns;
#if ROUND_STAT
	struct run_stat rs;
#endif /* ROUND_STAT */
#ifdef NETSTAT_TOTAL
	int j;
	uint32_t gflow_cnt = 0;
	struct net_stat g_nstat;
#if ROUND_STAT
	struct run_stat g_runstat;
#endif /* ROUND_STAT */
#endif /* NETSTAT_TOTAL */

	if (TS_TO_MSEC(cur_ts - mtcp->p_nstat_ts) < SEC_TO_MSEC(TIMEOUT)) {
		return;
	}

	mtcp->p_nstat_ts = cur_ts;
	gflow_cnt = 0;
	memset(&g_nstat, 0, sizeof(struct net_stat));
	for (i = 0; i < CONFIG.num_cores; i++) {
		if (running[i]) {
			PrintThreadNetworkStats(g_mtcp[i], &ns);
#if NETSTAT_TOTAL
			gflow_cnt += g_mtcp[i]->flow_cnt;
			for (j = 0; j < CONFIG.eths_num; j++) {
				g_nstat.rx_packets[j] += ns.rx_packets[j];
				g_nstat.rx_errors[j] += ns.rx_errors[j];
				g_nstat.rx_bytes[j] += ns.rx_bytes[j];
				g_nstat.tx_packets[j] += ns.tx_packets[j];
				g_nstat.tx_drops[j] += ns.tx_drops[j];
				g_nstat.tx_bytes[j] += ns.tx_bytes[j];
			}
#ifdef ENABLELRO
			g_nstat.rx_gdptbytes += ns.rx_gdptbytes;
			g_nstat.tx_gdptbytes += ns.tx_gdptbytes;
#endif
#endif
		}
	}
#if NETSTAT_TOTAL
	for (i = 0; i < CONFIG.eths_num; i++) {
		if (CONFIG.eths[i].stat_print) {
			fprintf(stderr, "[ ALL ] %s flows: %6u, "
					"RX: %7ld(pps) (err: %5ld), %5.2lf(Gbps), "
					"TX: %7ld(pps), %5.2lf(Gbps)\n", CONFIG.eths[i].dev_name, 
					gflow_cnt, g_nstat.rx_packets[i], g_nstat.rx_errors[i], 
					GBPS(g_nstat.rx_bytes[i]), g_nstat.tx_packets[i], 
					GBPS(g_nstat.tx_bytes[i]));
		}
	}
#ifdef ENABLELRO
	fprintf(stderr, "[ ALL ] Goodput RX: %5.2lf(Gbps), TX: %5.2lf(Gbps)\n",
			GBPS(g_nstat.rx_gdptbytes), GBPS(g_nstat.tx_gdptbytes));
#endif
#endif

#if ROUND_STAT
	memset(&g_runstat, 0, sizeof(struct run_stat));
	for (i = 0; i < CONFIG.num_cores; i++) {
		if (running[i]) {
			PrintThreadRoundStats(g_mtcp[i], &rs);
#if 0
			g_runstat.rounds += rs.rounds;
			g_runstat.rounds_rx += rs.rounds_rx;
			g_runstat.rounds_rx_try += rs.rounds_rx_try;
			g_runstat.rounds_tx += rs.rounds_tx;
			g_runstat.rounds_tx_try += rs.rounds_tx_try;
			g_runstat.rounds_select += rs.rounds_select;
			g_runstat.rounds_select_rx += rs.rounds_select_rx;
			g_runstat.rounds_select_tx += rs.rounds_select_tx;
#endif
		}
	}
#if 0
	fprintf(stderr, "[ ALL ] Rounds: %4ldK, "
			"rx: %3ldK (try: %4ldK), tx: %3ldK (try: %4ldK), "
			"ps_select: %4ld (rx: %4ld, tx: %4ld)\n", 
			g_runstat.rounds / 1000, g_runstat.rounds_rx / 1000, 
			g_runstat.rounds_rx_try / 1000, g_runstat.rounds_tx / 1000, 
			g_runstat.rounds_tx_try / 1000, g_runstat.rounds_select, 
			g_runstat.rounds_select_rx, g_runstat.rounds_select_tx);
#endif
#endif /* ROUND_STAT */

#if EVENT_STAT
	for (i = 0; i < CONFIG.num_cores; i++) {
		if (running[i] && g_mtcp[i]->ep) {
			PrintEventStat(i, &g_mtcp[i]->ep->stat);
		}
	}
#endif

	fflush(stderr);
}
#endif /* NETSTAT */
/*----------------------------------------------------------------------------*/
#if BLOCKING_SUPPORT
static inline void 
FlushAcceptEvents(mtcp_manager_t mtcp)
{
	STAT_COUNT(mtcp->runstat.rounds_accept);

	pthread_mutex_lock(&mtcp->listener->accept_lock);
	if (!StreamQueueIsEmpty(mtcp->listener->acceptq)) {
		pthread_cond_signal(&mtcp->listener->accept_cond);
	}
	pthread_mutex_unlock(&mtcp->listener->accept_lock);
}
/*----------------------------------------------------------------------------*/
static inline void
FlushWriteEvents(mtcp_manager_t mtcp, int thresh)
{
	tcp_stream *walk;
	tcp_stream *next, *last;
	int cnt;

	STAT_COUNT(mtcp->runstat.rounds_write);

	/* Notify available sending buffer (recovered peer window) */
	cnt = 0;
	walk = TAILQ_FIRST(&mtcp->snd_br_list);
	last = TAILQ_LAST(&mtcp->snd_br_list, snd_br_head);
	while (walk) {
		if (++cnt > thresh)
			break;

		next = TAILQ_NEXT(walk, sndvar->snd_br_link);
		TRACE_LOOP("Inside send broadcasting list. cnt: %u\n", cnt);
		TAILQ_REMOVE(&mtcp->snd_br_list, walk, sndvar->snd_br_link);
		mtcp->snd_br_list_cnt--;
		if (walk->on_snd_br_list) {
			TRACE_SNDBUF("Broadcasting available sending buffer!\n");
			if (!(walk->epoll & MTCP_EPOLLOUT)) {
				pthread_cond_signal(&walk->write_cond);
				walk->on_snd_br_list = FALSE;
			}
		}

		if (walk == last)
			break;
		walk = next;
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
FlushReadEvents(mtcp_manager_t mtcp, int thresh)
{	
	tcp_stream *walk;
	tcp_stream *next, *last;
	int cnt;

	STAT_COUNT(mtcp->runstat.rounds_read);

	/* Notify receiving event */
	cnt = 0;
	walk = TAILQ_FIRST(&mtcp->rcv_br_list);
	last = TAILQ_LAST(&mtcp->rcv_br_list, rcv_br_head);
	while (walk) {
		if (++cnt > thresh)
			break;

		next = TAILQ_NEXT(walk, rcvvar->rcv_br_link);
		TRACE_LOOP("Inside recv broadcasting list. cnt: %u\n", cnt);
		TAILQ_REMOVE(&mtcp->rcv_br_list, walk, rcvvar->rcv_br_link);
		mtcp->rcv_br_list_cnt--;
		if (walk->on_rcv_br_list) {
			if (!(walk->epoll & MTCP_EPOLLIN)) {
				TRACE_TEMP("Broadcasting read contition\n");
				pthread_cond_signal(&walk->read_cond);
				walk->on_rcv_br_list = FALSE;
			}
		}
		
		if (walk == last)
			break;
		walk = next;
	}
}
#endif
/*----------------------------------------------------------------------------*/
static inline void 
FlushEpollEvents(mtcp_manager_t mtcp, uint32_t cur_ts)
{
	struct mtcp_epoll *ep = mtcp->ep;
	struct event_queue *usrq = ep->usr_queue;
	struct event_queue *mtcpq = ep->mtcp_queue;

	pthread_mutex_lock(&ep->epoll_lock);
	if (ep->mtcp_queue->num_events > 0) {
		/* while mtcp_queue have events */
		/* and usr_queue is not full */
		while (mtcpq->num_events > 0 && usrq->num_events < usrq->size) {
			/* copy the event from mtcp_queue to usr_queue */
			usrq->events[usrq->end++] = mtcpq->events[mtcpq->start++];

			if (usrq->end >= usrq->size)
				usrq->end = 0;
			usrq->num_events++;

			if (mtcpq->start >= mtcpq->size)
				mtcpq->start = 0;
			mtcpq->num_events--;
		}
	}

	/* if there are pending events, wake up user */
	if (ep->waiting && (ep->usr_queue->num_events > 0 || 
				ep->usr_shadow_queue->num_events > 0)) {
		STAT_COUNT(mtcp->runstat.rounds_epoll);
		TRACE_EPOLL("Broadcasting events. num: %d, cur_ts: %u, prev_ts: %u\n", 
				ep->usr_queue->num_events, cur_ts, mtcp->ts_last_event);
		//mtcp->ts_last_event = cur_ts;
		ep->stat.wakes++;
		pthread_cond_signal(&ep->epoll_cond);
	}
	pthread_mutex_unlock(&ep->epoll_lock);
}
/*----------------------------------------------------------------------------*/
static inline void 
HandleApplicationCalls(mtcp_manager_t mtcp, uint32_t cur_ts)
{
	tcp_stream *stream;
	int cnt, max_cnt;
	int handled, delayed;
	int control, send, ack;

	/* connect handling */
	while ((stream = StreamDequeue(mtcp->connectq))) {
		AddtoControlList(mtcp, stream, cur_ts);
	}

	/* send queue handling */
	while ((stream = StreamDequeue(mtcp->sendq))) {
		stream->sndvar->on_sendq = FALSE;
		AddtoSendList(mtcp, stream);
	}
	
	/* ack queue handling */
	while ((stream = StreamDequeue(mtcp->ackq))) {
		stream->sndvar->on_ackq = FALSE;
		EnqueueACK(mtcp, stream, cur_ts, ACK_OPT_AGGREGATE);
	}

	/* close handling */
	handled = delayed = 0;
	control = send = ack = 0;
	while ((stream = StreamDequeue(mtcp->closeq))) {
		struct tcp_send_vars *sndvar = stream->sndvar;
		sndvar->on_closeq = FALSE;
		
		if (sndvar->sndbuf) {
			sndvar->fss = sndvar->sndbuf->head_seq + sndvar->sndbuf->len;
		} else {
			sndvar->fss = stream->snd_nxt;
		}

		if (CONFIG.tcp_timeout > 0)
			RemoveFromTimeoutList(mtcp, stream);

		if (stream->have_reset) {
			handled++;
			if (stream->state != TCP_ST_CLOSED) {
				stream->close_reason = TCP_RESET;
				stream->state = TCP_ST_CLOSED;
				TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", stream->id);
				DestroyTCPStream(mtcp, stream);
			} else {
				TRACE_ERROR("Stream already closed.\n");
			}

		} else if (sndvar->on_control_list) {
			sndvar->on_closeq_int = TRUE;
			StreamInternalEnqueue(mtcp->closeq_int, stream);
			delayed++;
			if (sndvar->on_control_list)
				control++;
			if (sndvar->on_send_list)
				send++;
			if (sndvar->on_ack_list)
				ack++;

		} else if (sndvar->on_send_list || sndvar->on_ack_list) {
			handled++;
			if (stream->state == TCP_ST_ESTABLISHED) {
				stream->state = TCP_ST_FIN_WAIT_1;
				TRACE_STATE("Stream %d: TCP_ST_FIN_WAIT_1\n", stream->id);

			} else if (stream->state == TCP_ST_CLOSE_WAIT) {
				stream->state = TCP_ST_LAST_ACK;
				TRACE_STATE("Stream %d: TCP_ST_LAST_ACK\n", stream->id);
			}
			stream->control_list_waiting = TRUE;

		} else if (stream->state != TCP_ST_CLOSED) {
			handled++;
			if (stream->state == TCP_ST_ESTABLISHED) {
				stream->state = TCP_ST_FIN_WAIT_1;
				TRACE_STATE("Stream %d: TCP_ST_FIN_WAIT_1\n", stream->id);

			} else if (stream->state == TCP_ST_CLOSE_WAIT) {
				stream->state = TCP_ST_LAST_ACK;
				TRACE_STATE("Stream %d: TCP_ST_LAST_ACK\n", stream->id);
			}
			//sndvar->rto = TCP_FIN_RTO;
			//UpdateRetransmissionTimer(mtcp, stream, mtcp->cur_ts);
			AddtoControlList(mtcp, stream, cur_ts);
		} else {
			TRACE_ERROR("Already closed connection!\n");
		}
	}
	TRACE_ROUND("Handling close connections. cnt: %d\n", cnt);

	cnt = 0;
	max_cnt = mtcp->closeq_int->count;
	while (cnt++ < max_cnt) {
		stream = StreamInternalDequeue(mtcp->closeq_int);

		if (stream->sndvar->on_control_list) {
			StreamInternalEnqueue(mtcp->closeq_int, stream);

		} else if (stream->state != TCP_ST_CLOSED) {
			handled++;
			stream->sndvar->on_closeq_int = FALSE;
			if (stream->state == TCP_ST_ESTABLISHED) {
				stream->state = TCP_ST_FIN_WAIT_1;
				TRACE_STATE("Stream %d: TCP_ST_FIN_WAIT_1\n", stream->id);

			} else if (stream->state == TCP_ST_CLOSE_WAIT) {
				stream->state = TCP_ST_LAST_ACK;
				TRACE_STATE("Stream %d: TCP_ST_LAST_ACK\n", stream->id);
			}
			AddtoControlList(mtcp, stream, cur_ts);
		} else {
			stream->sndvar->on_closeq_int = FALSE;
			TRACE_ERROR("Already closed connection!\n");
		}
	}

	/* reset handling */
	while ((stream = StreamDequeue(mtcp->resetq))) {
		stream->sndvar->on_resetq = FALSE;
		
		if (CONFIG.tcp_timeout > 0)
			RemoveFromTimeoutList(mtcp, stream);

		if (stream->have_reset) {
			if (stream->state != TCP_ST_CLOSED) {
				stream->close_reason = TCP_RESET;
				stream->state = TCP_ST_CLOSED;
				TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", stream->id);
				DestroyTCPStream(mtcp, stream);
			} else {
				TRACE_ERROR("Stream already closed.\n");
			}

		} else if (stream->sndvar->on_control_list || 
				stream->sndvar->on_send_list || stream->sndvar->on_ack_list) {
			/* wait until all the queues are flushed */
			stream->sndvar->on_resetq_int = TRUE;
			StreamInternalEnqueue(mtcp->resetq_int, stream);

		} else {
			if (stream->state != TCP_ST_CLOSED) {
				stream->close_reason = TCP_ACTIVE_CLOSE;
				stream->state = TCP_ST_CLOSED;
				TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", stream->id);
				AddtoControlList(mtcp, stream, cur_ts);
			} else {
				TRACE_ERROR("Stream already closed.\n");
			}
		}
	}
	TRACE_ROUND("Handling reset connections. cnt: %d\n", cnt);

	cnt = 0;
	max_cnt = mtcp->resetq_int->count;
	while (cnt++ < max_cnt) {
		stream = StreamInternalDequeue(mtcp->resetq_int);
		
		if (stream->sndvar->on_control_list || 
				stream->sndvar->on_send_list || stream->sndvar->on_ack_list) {
			/* wait until all the queues are flushed */
			StreamInternalEnqueue(mtcp->resetq_int, stream);

		} else {
			stream->sndvar->on_resetq_int = FALSE;

			if (stream->state != TCP_ST_CLOSED) {
				stream->close_reason = TCP_ACTIVE_CLOSE;
				stream->state = TCP_ST_CLOSED;
				TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", stream->id);
				AddtoControlList(mtcp, stream, cur_ts);
			} else {
				TRACE_ERROR("Stream already closed.\n");
			}
		}
	}

	/* destroy streams in destroyq */
	while ((stream = StreamDequeue(mtcp->destroyq))) {
		DestroyTCPStream(mtcp, stream);
	}

	mtcp->wakeup_flag = FALSE;
}
/*----------------------------------------------------------------------------*/
static inline void 
WritePacketsToChunks(mtcp_manager_t mtcp, uint32_t cur_ts)
{
	int thresh = CONFIG.max_concurrency;
	int i;

	/* Set the threshold to CONFIG.max_concurrency to send ACK immediately */
	/* Otherwise, set to appropriate value (e.g. thresh) */
	assert(mtcp->g_sender != NULL);
	if (mtcp->g_sender->control_list_cnt)
		WriteTCPControlList(mtcp, mtcp->g_sender, cur_ts, thresh);
	if (mtcp->g_sender->ack_list_cnt)
		WriteTCPACKList(mtcp, mtcp->g_sender, cur_ts, thresh);
	if (mtcp->g_sender->send_list_cnt)
		WriteTCPDataList(mtcp, mtcp->g_sender, cur_ts, thresh);

	for (i = 0; i < CONFIG.eths_num; i++) {
		assert(mtcp->n_sender[i] != NULL);
		if (mtcp->n_sender[i]->control_list_cnt)
			WriteTCPControlList(mtcp, mtcp->n_sender[i], cur_ts, thresh);
		if (mtcp->n_sender[i]->ack_list_cnt)
			WriteTCPACKList(mtcp, mtcp->n_sender[i], cur_ts, thresh);
		if (mtcp->n_sender[i]->send_list_cnt)
			WriteTCPDataList(mtcp, mtcp->n_sender[i], cur_ts, thresh);
	}
}
/*----------------------------------------------------------------------------*/
#if TESTING
static int
DestroyRemainingFlows(mtcp_manager_t mtcp)
{
	struct hashtable *ht = mtcp->tcp_flow_table;
	tcp_stream *walk;
	int cnt, i;

	cnt = 0;
#if 0
	thread_printf(mtcp, mtcp->log_fp, 
			"CPU %d: Flushing remaining flows.\n", mtcp->ctx->cpu);
#endif
	for (i = 0; i < NUM_BINS; i++) {
		TAILQ_FOREACH(walk, &ht->ht_table[i], rcvvar->he_link) {
#ifdef DUMP_STREAM
			thread_printf(mtcp, mtcp->log_fp, 
					"CPU %d: Destroying stream %d\n", mtcp->ctx->cpu, walk->id);
			DumpStream(mtcp, walk);
#endif
			DestroyTCPStream(mtcp, walk);
			cnt++;
		}
	}

	return cnt;
}
#endif
/*----------------------------------------------------------------------------*/
static void 
InterruptApplication(mtcp_manager_t mtcp)
{
	int i;
	struct tcp_listener *listener = NULL;

	/* interrupt if the mtcp_epoll_wait() is waiting */
	if (mtcp->ep) {
		pthread_mutex_lock(&mtcp->ep->epoll_lock);
		if (mtcp->ep->waiting) {
			pthread_cond_signal(&mtcp->ep->epoll_cond);
		}
		pthread_mutex_unlock(&mtcp->ep->epoll_lock);
	}

	/* interrupt if the accept() is waiting */
	/* this may be a looong loop but this is called only on exit */
	for (i = 0; i < MAX_PORT; i++) {
		listener = ListenerHTSearch(mtcp->listeners, &i);
		if (listener != NULL) {
			pthread_mutex_lock(&listener->accept_lock);
			if (!(listener->socket->opts & MTCP_NONBLOCK)) {
				pthread_cond_signal(&listener->accept_cond);
			}
			pthread_mutex_unlock(&listener->accept_lock);			
		}
	}
}
static void check_dsa()
{
        mtcp_manager_t mtcp;
	static int check_cnt;
	static int success_cnt;;
	int rc;

 	if(check_cnt % 10000000 == 0) {

                printf("dsa check count : %d\n", check_cnt);
        }
	check_cnt++;

        if (dsa_running) {
		//printf("check_dsa,dsa_running=1, tid:%ld.\n", mctx_tmp->dsa->single_task->tid);
                //check dsa complete status

		rc = dsa_wait_memcpy_async(mctx_tmp->dsa);
		if(rc != DSA_STATUS_OK)
		{
			return; //if not complete,just return,check status in next protocol routine loop
		}
		success_cnt++;
		if(success_cnt % 1000 == 0)
		{
			printf("dsa memcpy success %d times\n", success_cnt);
		}
		
		//copy data to sendbuf complete, update send buffer variables
		sndvar_tmp->sndbuf->tail_off = tail_off_tmp;
		sndvar_tmp->sndbuf->len += len_tmp;
		sndvar_tmp->sndbuf->cum_len += len_tmp;
		
                mtcp = GetMTCPManager(mctx_tmp);
		if(mtcp == NULL) return;
		dsa_running = false;
                if (!(sndvar_tmp->on_sendq || sndvar_tmp->on_send_list)) {
                        SQ_LOCK(&mtcp->ctx->sendq_lock);
                        sndvar_tmp->on_sendq = TRUE;
                        StreamEnqueue(mtcp->sendq, cur_stream_tmp);         /* this always success */
                        SQ_UNLOCK(&mtcp->ctx->sendq_lock);
                        mtcp->wakeup_flag = TRUE;
                }
        }
    return;

}
/*----------------------------------------------------------------------------*/
static void 
RunMainLoop(struct mtcp_thread_context *ctx)
{
	mtcp_manager_t mtcp = ctx->mtcp_manager;
	int i;
	int recv_cnt;
	int rx_inf, tx_inf;
	struct timeval cur_ts = {0};
	uint32_t ts, ts_prev;
	int thresh;

	gettimeofday(&cur_ts, NULL);
	TRACE_DBG("CPU %d: mtcp thread running.\n", ctx->cpu);

	ts = ts_prev = 0;
	while ((!ctx->done || mtcp->flow_cnt) && !ctx->exit) {
		
		STAT_COUNT(mtcp->runstat.rounds);
		recv_cnt = 0;
			
		gettimeofday(&cur_ts, NULL);
		ts = TIMEVAL_TO_TS(&cur_ts);
		mtcp->cur_ts = ts;

		for (rx_inf = 0; rx_inf < CONFIG.eths_num; rx_inf++) {

			static uint16_t len;
			static uint8_t *pktbuf;
			recv_cnt = mtcp->iom->recv_pkts(ctx, rx_inf);
			STAT_COUNT(mtcp->runstat.rounds_rx_try);

			for (i = 0; i < recv_cnt; i++) {
				pktbuf = mtcp->iom->get_rptr(mtcp->ctx, rx_inf, i, &len);
				if (pktbuf != NULL)
					ProcessPacket(mtcp, rx_inf, ts, pktbuf, len);
#ifdef NETSTAT
				else
					mtcp->nstat.rx_errors[rx_inf]++;
#endif
			}
		}
		STAT_COUNT(mtcp->runstat.rounds_rx);

		/* interaction with application */
		if (mtcp->flow_cnt > 0) {
			
			/* check retransmission timeout and timewait expire */
#if 0
			thresh = (int)mtcp->flow_cnt / (TS_TO_USEC(PER_STREAM_TCHECK));
			assert(thresh >= 0);
			if (thresh == 0)
				thresh = 1;
			if (recv_cnt > 0 && thresh > recv_cnt)
				thresh = recv_cnt;
#endif
			thresh = CONFIG.max_concurrency;

			/* Eunyoung, you may fix this later 
			 * if there is no rcv packet, we will send as much as possible
			 */
			if (thresh == -1)
				thresh = CONFIG.max_concurrency;

			CheckRtmTimeout(mtcp, ts, thresh);
			CheckTimewaitExpire(mtcp, ts, CONFIG.max_concurrency);

			if (CONFIG.tcp_timeout > 0 && ts != ts_prev) {
				CheckConnectionTimeout(mtcp, ts, thresh);
			}
		}

		/* if epoll is in use, flush all the queued events */
		if (mtcp->ep) {
			FlushEpollEvents(mtcp, ts);
		}

		if (mtcp->flow_cnt > 0) {
			/* hadnle stream queues  */
			HandleApplicationCalls(mtcp, ts);
		}

		check_dsa(); //check whether dsa copy task is completed

		WritePacketsToChunks(mtcp, ts);

		/* send packets from write buffer */
		/* send until tx is available */
		for (tx_inf = 0; tx_inf < CONFIG.eths_num; tx_inf++) {
			mtcp->iom->send_pkts(ctx, tx_inf);
		}

		if (ts != ts_prev) {
			ts_prev = ts;
			if (ctx->cpu == mtcp_master) {
				ARPTimer(mtcp, ts);
#if 0  //#ifdef NETSTAT
				PrintNetworkStats(mtcp, ts);
#endif
			}
		}

		mtcp->iom->select(ctx);

		if (ctx->interrupt) {
			InterruptApplication(mtcp);
		}
	}

#if TESTING
	DestroyRemainingFlows(mtcp);
#endif

	TRACE_DBG("MTCP thread %d out of main loop.\n", ctx->cpu);
	/* flush logs */
	flush_log_data(mtcp);
	TRACE_DBG("MTCP thread %d flushed logs.\n", ctx->cpu);
	InterruptApplication(mtcp);
	TRACE_INFO("MTCP thread %d finished.\n", ctx->cpu);
}
/*----------------------------------------------------------------------------*/
struct mtcp_sender *
CreateMTCPSender(int ifidx)
{
	struct mtcp_sender *sender;

	sender = (struct mtcp_sender *)calloc(1, sizeof(struct mtcp_sender));
	if (!sender) {
		return NULL;
	}

	sender->ifidx = ifidx;

	TAILQ_INIT(&sender->control_list);
	TAILQ_INIT(&sender->send_list);
	TAILQ_INIT(&sender->ack_list);

	sender->control_list_cnt = 0;
	sender->send_list_cnt = 0;
	sender->ack_list_cnt = 0;

	return sender;
}
/*----------------------------------------------------------------------------*/
void 
DestroyMTCPSender(struct mtcp_sender *sender)
{
	free(sender);
}
/*----------------------------------------------------------------------------*/
static mtcp_manager_t 
InitializeMTCPManager(struct mtcp_thread_context* ctx)
{
	mtcp_manager_t mtcp;
	char log_name[MAX_FILE_NAME];
	int i;

	mtcp = (mtcp_manager_t)calloc(1, sizeof(struct mtcp_manager));
	if (!mtcp) {
		perror("malloc");
		fprintf(stderr, "Failed to allocate mtcp_manager.\n");
		return NULL;
	}
	g_mtcp[ctx->cpu] = mtcp;

	mtcp->tcp_flow_table = CreateHashtable(HashFlow, EqualFlow, NUM_BINS_FLOWS);
	if (!mtcp->tcp_flow_table) {
		CTRACE_ERROR("Falied to allocate tcp flow table.\n");
		return NULL;
	}

#if USE_CCP
	mtcp->tcp_sid_table = CreateHashtable(HashSID, EqualSID, NUM_BINS_FLOWS);
	if (!mtcp->tcp_sid_table) {
		CTRACE_ERROR("Failed to allocate tcp sid lookup table.\n");
		return NULL;
	}
#endif

	mtcp->listeners = CreateHashtable(HashListener, EqualListener, NUM_BINS_LISTENERS);
	if (!mtcp->listeners) {
		CTRACE_ERROR("Failed to allocate listener table.\n");
		return NULL;
	}

	mtcp->ctx = ctx;
#if !defined(DISABLE_DPDK) && !ENABLE_ONVM
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	sprintf(pool_name, "flow_pool_%d", ctx->cpu);
	mtcp->flow_pool = MPCreate(pool_name, sizeof(tcp_stream),
				   sizeof(tcp_stream) * CONFIG.max_concurrency);
	if (!mtcp->flow_pool) {
		CTRACE_ERROR("Failed to allocate tcp flow pool.\n");
		return NULL;
	}
	sprintf(pool_name, "rv_pool_%d", ctx->cpu);	
	mtcp->rv_pool = MPCreate(pool_name, sizeof(struct tcp_recv_vars), 
			sizeof(struct tcp_recv_vars) * CONFIG.max_concurrency);
	if (!mtcp->rv_pool) {
		CTRACE_ERROR("Failed to allocate tcp recv variable pool.\n");
		return NULL;
	}
	sprintf(pool_name, "sv_pool_%d", ctx->cpu);
	mtcp->sv_pool = MPCreate(pool_name, sizeof(struct tcp_send_vars), 
			sizeof(struct tcp_send_vars) * CONFIG.max_concurrency);
	if (!mtcp->sv_pool) {
		CTRACE_ERROR("Failed to allocate tcp send variable pool.\n");
		return NULL;
	}
#else
	mtcp->flow_pool = MPCreate(sizeof(tcp_stream),
				   sizeof(tcp_stream) * CONFIG.max_concurrency);
	if (!mtcp->flow_pool) {
		CTRACE_ERROR("Failed to allocate tcp flow pool.\n");
		return NULL;
	}
	mtcp->rv_pool = MPCreate(sizeof(struct tcp_recv_vars), 
			sizeof(struct tcp_recv_vars) * CONFIG.max_concurrency);
	if (!mtcp->rv_pool) {
		CTRACE_ERROR("Failed to allocate tcp recv variable pool.\n");
		return NULL;
	}
	mtcp->sv_pool = MPCreate(sizeof(struct tcp_send_vars), 
			sizeof(struct tcp_send_vars) * CONFIG.max_concurrency);
	if (!mtcp->sv_pool) {
		CTRACE_ERROR("Failed to allocate tcp send variable pool.\n");
		return NULL;
	}	
#endif
	mtcp->rbm_snd = SBManagerCreate(mtcp, CONFIG.sndbuf_size, CONFIG.max_num_buffers);
	if (!mtcp->rbm_snd) {
		CTRACE_ERROR("Failed to create send ring buffer.\n");
		return NULL;
	}

	mtcp->rbm_rcv = RBManagerCreate(mtcp, CONFIG.rcvbuf_size, CONFIG.max_num_buffers);
	if (!mtcp->rbm_rcv) {
		CTRACE_ERROR("Failed to create recv ring buffer.\n");
		return NULL;
	}

	InitializeTCPStreamManager();

	mtcp->smap = (socket_map_t)calloc(CONFIG.max_concurrency, sizeof(struct socket_map));
	if (!mtcp->smap) {
		perror("calloc");
		CTRACE_ERROR("Failed to allocate memory for stream map.\n");
		return NULL;
	}
	TAILQ_INIT(&mtcp->free_smap);
	for (i = 0; i < CONFIG.max_concurrency; i++) {
		mtcp->smap[i].id = i;
		mtcp->smap[i].socktype = MTCP_SOCK_UNUSED;
		memset(&mtcp->smap[i].saddr, 0, sizeof(struct sockaddr_in));
		mtcp->smap[i].stream = NULL;
		TAILQ_INSERT_TAIL(&mtcp->free_smap, &mtcp->smap[i], free_smap_link);
	}

	mtcp->ep = NULL;

	snprintf(log_name, MAX_FILE_NAME, LOG_FILE_NAME"_%d", ctx->cpu);
	mtcp->log_fp = fopen(log_name, "w");
	if (!mtcp->log_fp) {
		perror("fopen");
		CTRACE_ERROR("Failed to create file for logging.\n");
		return NULL;
	}
	mtcp->sp_fd = g_logctx[ctx->cpu]->pair_sp_fd;
	mtcp->logger = g_logctx[ctx->cpu];
	
	mtcp->connectq = CreateStreamQueue(BACKLOG_SIZE);
	if (!mtcp->connectq) {
		CTRACE_ERROR("Failed to create connect queue.\n");
		return NULL;
	}
	mtcp->sendq = CreateStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->sendq) {
		CTRACE_ERROR("Failed to create send queue.\n");
		return NULL;
	}
	mtcp->ackq = CreateStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->ackq) {
		CTRACE_ERROR("Failed to create ack queue.\n");
		return NULL;
	}
	mtcp->closeq = CreateStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->closeq) {
		CTRACE_ERROR("Failed to create close queue.\n");
		return NULL;
	}
	mtcp->closeq_int = CreateInternalStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->closeq_int) {
		CTRACE_ERROR("Failed to create close queue.\n");
		return NULL;
	}
	mtcp->resetq = CreateStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->resetq) {
		CTRACE_ERROR("Failed to create reset queue.\n");
		return NULL;
	}
	mtcp->resetq_int = CreateInternalStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->resetq_int) {
		CTRACE_ERROR("Failed to create reset queue.\n");
		return NULL;
	}
	mtcp->destroyq = CreateStreamQueue(CONFIG.max_concurrency);
	if (!mtcp->destroyq) {
		CTRACE_ERROR("Failed to create destroy queue.\n");
		return NULL;
	}

	mtcp->g_sender = CreateMTCPSender(-1);
	if (!mtcp->g_sender) {
		CTRACE_ERROR("Failed to create global sender structure.\n");
		return NULL;
	}
	for (i = 0; i < CONFIG.eths_num; i++) {
		mtcp->n_sender[i] = CreateMTCPSender(i);
		if (!mtcp->n_sender[i]) {
			CTRACE_ERROR("Failed to create per-nic sender structure.\n");
			return NULL;
		}
	}
		
	mtcp->rto_store = InitRTOHashstore();
	TAILQ_INIT(&mtcp->timewait_list);
	TAILQ_INIT(&mtcp->timeout_list);

#if BLOCKING_SUPPORT
	TAILQ_INIT(&mtcp->rcv_br_list);
	TAILQ_INIT(&mtcp->snd_br_list);
#endif

	return mtcp;
}
/*----------------------------------------------------------------------------*/
#if USE_CCP

uint32_t libstartccp_run_forever(const char *alg_to_run, uint32_t log_fd);

static void *
CCPRunThread(void *arg) {
    // Add ipc argument (always unix, so no need for user to provide manually)
    char args[1024] = {0};
    int arglen = strlen(CONFIG.cc)-1;
    strncpy(args, CONFIG.cc, arglen);
    strncpy(args+arglen, " --ipc=unix", 11);
    args[arglen+11] = '\0';

    // Open fd for log file
	FILE *ccp_log = fopen("cc.log", "w");
	if (ccp_log == NULL) {
		perror("fopen cc.log");
		return 0;
	}
    TRACE_CCP("starting ccp thread with args: %s\n", args);
    TRACE_CCP("printing output to ./cc.log\n");
    libstartccp_run_forever(args, fileno(ccp_log));

    fclose(ccp_log);

    return 0;
}

static void *
CCPRecvLoopThread(void *arg) {
	mtcp_manager_t mtcp = (mtcp_manager_t)arg;
	mtcp_thread_context_t ctx = mtcp->ctx;

	int cpu = ctx->cpu;
	mtcp_core_affinitize(cpu);

	TRACE_CCP("ccp recv loop thread started on cpu %d\n", cpu);

	char recvBuf[CCP_MAX_MSG_SIZE];
	int bytes_recvd;
	while (!ctx->done && !ctx->exit) {
		do {
			bytes_recvd = recvfrom(mtcp->from_ccp, recvBuf, CCP_MAX_MSG_SIZE, 0, NULL, NULL);
			if (bytes_recvd <= 0) {
				if (bytes_recvd < 0) {
					TRACE_ERROR("recv returned %d\n", bytes_recvd);
				}
				break;
			}
			if (!mtcp->to_ccp) {
				setup_ccp_send_socket(mtcp);
			}
			ccp_read_msg(recvBuf, bytes_recvd);
		} while(1);
	}
	return 0;
}
#endif
/*----------------------------------------------------------------------------*/
static void *
MTCPRunThread(void *arg)
{
	mctx_t mctx = (mctx_t)arg;
	int cpu = mctx->cpu;
	int working;
	struct mtcp_manager *mtcp;
	struct mtcp_thread_context *ctx;

	/* affinitize the thread to this core first */
#ifndef DISABLE_DPDK
	if (rte_lcore_id() == LCORE_ID_ANY)
#endif
	{
		mtcp_core_affinitize(cpu);
	}

	/* memory alloc after core affinitization would use local memory
	   most time */
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		perror("calloc");
		TRACE_ERROR("Failed to calloc mtcp context.\n");
		exit(-1);
	}
	ctx->thread = pthread_self();
	ctx->cpu = cpu;
	mtcp = ctx->mtcp_manager = InitializeMTCPManager(ctx);
	if (!mtcp) {
		TRACE_ERROR("Failed to initialize mtcp manager.\n");
		exit(-1);
	}

	/* assign mtcp context's underlying I/O module */
	mtcp->iom = current_iomodule_func;

	/* I/O initializing */
	mtcp->iom->init_handle(ctx);

	if (pthread_mutex_init(&ctx->smap_lock, NULL)) {
		perror("pthread_mutex_init of ctx->smap_lock\n");
		exit(-1);
	}

	if (pthread_mutex_init(&ctx->flow_pool_lock, NULL)) {
		perror("pthread_mutex_init of ctx->flow_pool_lock\n");
		exit(-1);
	}
	
	if (pthread_mutex_init(&ctx->socket_pool_lock, NULL)) {
		perror("pthread_mutex_init of ctx->socket_pool_lock\n");
		exit(-1);
	}

	SQ_LOCK_INIT(&ctx->connect_lock, "ctx->connect_lock", exit(-1));
	SQ_LOCK_INIT(&ctx->close_lock, "ctx->close_lock", exit(-1));
	SQ_LOCK_INIT(&ctx->reset_lock, "ctx->reset_lock", exit(-1));
	SQ_LOCK_INIT(&ctx->sendq_lock, "ctx->sendq_lock", exit(-1));
	SQ_LOCK_INIT(&ctx->ackq_lock, "ctx->ackq_lock", exit(-1));
	SQ_LOCK_INIT(&ctx->destroyq_lock, "ctx->destroyq_lock", exit(-1));

	/* remember this context pointer for signal processing */
	g_pctx[cpu] = ctx;
	mlockall(MCL_CURRENT);

#if USE_CCP
	setup_ccp_connection(mtcp);

    if (cpu == 0 && pthread_create(&ccp_run_thread, NULL, CCPRunThread, (void *)mtcp) != 0) {
        TRACE_ERROR("Failed to create thread running CCP on cpu 0");
    }
    if (pthread_create(&ccp_recv_thread[cpu], NULL, CCPRecvLoopThread, (void *)mtcp) != 0)
    {
        TRACE_ERROR("Failed to create thread for CCP receive loop on cpu %d\n", cpu);
        return NULL;
    }
#endif

	// attach (nic device, queue)
	working = AttachDevice(ctx);
	if (working != 0) {
		perror("attach");
		return NULL;
	}

	TRACE_DBG("CPU %d: initialization finished.\n", cpu);

	fprintf(stderr, "CPU %d: initialization finished.\n", cpu);
	
	sem_post(&g_init_sem[ctx->cpu]);

	/* start the main loop */
	RunMainLoop(ctx);

	struct mtcp_context m;
	m.cpu = cpu;
	mtcp_free_context(&m);
	/* destroy hash tables */
	DestroyHashtable(g_mtcp[cpu]->tcp_flow_table);
#if USE_CCP
	DestroyHashtable(g_mtcp[cpu]->tcp_sid_table);
#endif
	DestroyHashtable(g_mtcp[cpu]->listeners);
	
	TRACE_DBG("MTCP thread %d finished.\n", ctx->cpu);
	
	return 0;
}
/*----------------------------------------------------------------------------*/
#ifndef DISABLE_DPDK
int MTCPDPDKRunThread(void *arg)
{
	MTCPRunThread(arg);
	return 0;
}
#endif
/*----------------------------------------------------------------------------*/
mctx_t 
mtcp_create_context(int cpu)
{
	mctx_t mctx;
	int ret;

	if (cpu >=  CONFIG.num_cores) {
		TRACE_ERROR("Failed initialize new mtcp context. "
			    "Requested cpu id %d exceed the number of cores %d configured to use.\n",
			    cpu, CONFIG.num_cores);
		return NULL;
	}

        /* check if mtcp_create_context() was already initialized */
        if (g_logctx[cpu] != NULL) {
                TRACE_ERROR("%s was already initialized before!\n",
                            __FUNCTION__);
                return NULL;
        }

	ret = sem_init(&g_init_sem[cpu], 0, 0);
	if (ret) {
		TRACE_ERROR("Failed initialize init_sem.\n");
		return NULL;
	}

	mctx = (mctx_t)calloc(1, sizeof(struct mtcp_context));
	if (!mctx) {
		TRACE_ERROR("Failed to allocate memory for mtcp_context.\n");
		sem_destroy(&g_init_sem[cpu]);
		return NULL;
	}
	mctx->cpu = cpu;
	mctx->psfifo = sfifo_create();
	if(mctx->psfifo == NULL) {
		sem_destroy(&g_init_sem[cpu]);
		free(mctx);
		return NULL;
	}
	mctx->qctx.tx_queue_size = 128;
        mctx->qctx.tx_desc_buf_size = 1500;
        mctx->qctx.rx_queue_size = 128;
        mctx->qctx.rx_desc_buf_size = 1500;
        if(init_virtio(&(mctx->qctx)) != 0 ){
                TRACE_ERROR("init virtio queue context failed.\n");
		sfifo_free(mctx->psfifo);
		free(mctx);
		sem_destroy(&g_init_sem[cpu]);
                return NULL;
        }

	#ifdef DSA_ENABLE
	// init dsa
		const int DSA_TEST_SIZE = 20000;
		const int SHARED = 0;
		printf("*************************************DSA_INIT***************************\n");
		unsigned long buf_size = DSA_TEST_SIZE;
		int wq_type = SHARED;
		int rc = 0;

		mctx->dsa = dsa_init();
		if (mctx->dsa == NULL){
			printf("*************************************DSA_INIT is NULL***************************\n");
			sfifo_free(mctx->psfifo);
			deinit_virtio(&(mctx->qctx));
			free(mctx);
			sem_destroy(&g_init_sem[cpu]);

			return NULL;
		}
		rc = dsa_alloc(mctx->dsa, wq_type);
		if (rc < 0)
		{	
			sfifo_free(mctx->psfifo);
			dsa_free(mctx->dsa);
			deinit_virtio(&(mctx->qctx));
			free(mctx);
			sem_destroy(&g_init_sem[cpu]);

			exit(-1);
		}
		if (buf_size > mctx->dsa->max_xfer_size) {
                        printf("invalid transfer size: %lu\n", buf_size);
                        sfifo_free(mctx->psfifo);
			deinit_virtio(&(mctx->qctx));
                        dsa_free(mctx->dsa);
			free(mctx);
                        sem_destroy(&g_init_sem[cpu]);
                        exit(-1);
                }

		rc = alloc_task(mctx->dsa);
		if(rc != 0x0) {
			printf("alloc task failed!\n");
			sfifo_free(mctx->psfifo);
			deinit_virtio(&(mctx->qctx));
			dsa_free(mctx->dsa);
			free(mctx);
			sem_destroy(&g_init_sem[cpu]);

			exit(-1);
		}
		printf("**********************************CORE INIT DSA_DONE***************************\n");
	#endif

	/* initialize logger */
	g_logctx[cpu] = (struct log_thread_context *)
			calloc(1, sizeof(struct log_thread_context));
	if (!g_logctx[cpu]) {
		perror("calloc");
		TRACE_ERROR("Failed to allocate memory for log thread context.\n");
		sfifo_free(mctx->psfifo);
		deinit_virtio(&(mctx->qctx));
		dsa_free(mctx->dsa);
		free(mctx);
                sem_destroy(&g_init_sem[cpu]);

		return NULL;
	}
	InitLogThreadContext(g_logctx[cpu], cpu);
#if defined (PKTDUMP) || (DBGMSG) || (DBGFUNC) || \
	(STREAM) || (STATE) || (STAT) || (APP) || \
	(EPOLL) || (DUMP_STREAM)
	if (pthread_create(&log_thread[cpu], 
				NULL, ThreadLogMain, (void *)g_logctx[cpu])) {
		perror("pthread_create");
		TRACE_ERROR("Failed to create log thread\n");
		sfifo_free(mctx->psfifo);
		deinit_virtio(&(mctx->qctx));
		dsa_free(mctx->dsa);
		free(mctx);
                sem_destroy(&g_init_sem[cpu]);

		return NULL;
	}
#endif
#ifndef DISABLE_DPDK
	/* Wake up mTCP threads (wake up I/O threads) */
	if (current_iomodule_func == &dpdk_module_func) {
		int master;
		master = rte_get_main_lcore();
		
		if (master == whichCoreID(cpu)) {
			if (pthread_create(&g_thread[cpu], 
					   NULL, MTCPRunThread, (void *)mctx) != 0) {
				TRACE_ERROR("pthread_create of mtcp thread failed!\n");
				return NULL;
			}
		} else
			rte_eal_remote_launch(MTCPDPDKRunThread, mctx, whichCoreID(cpu));
	} else
#endif
		{
			if (pthread_create(&g_thread[cpu], 
					   NULL, MTCPRunThread, (void *)mctx) != 0) {
				TRACE_ERROR("pthread_create of mtcp thread failed!\n");
				return NULL;
			}
		}

	sem_wait(&g_init_sem[cpu]);
	sem_destroy(&g_init_sem[cpu]);

	running[cpu] = TRUE;

	if (mtcp_master < 0) {
		mtcp_master = cpu;
		TRACE_INFO("CPU %d is now the master thread.\n", mtcp_master);
	}

	return mctx;
}
/*----------------------------------------------------------------------------*/
void
mtcp_destroy_context(mctx_t mctx)
{
  	struct mtcp_thread_context *ctx = g_pctx[mctx->cpu];
  	if (ctx != NULL)
    		ctx->done = 1;
	free(mctx);
}
/*----------------------------------------------------------------------------*/
void 
mtcp_free_context(mctx_t mctx)
{
	struct mtcp_thread_context *ctx = g_pctx[mctx->cpu];
	struct mtcp_manager *mtcp = ctx->mtcp_manager;
	struct log_thread_context *log_ctx = mtcp->logger;
	int ret, i;

	if (g_pctx[mctx->cpu] == NULL) return;

	flush_log_data(mtcp);
	
	TRACE_DBG("CPU %d: mtcp_destroy_context()\n", mctx->cpu);

	/* close all stream sockets that are still open */
	if (!ctx->exit) {
		for (i = 0; i < CONFIG.max_concurrency; i++) {
			if (mtcp->smap[i].socktype == MTCP_SOCK_STREAM) {
				TRACE_DBG("Closing remaining socket %d (%s)\n", 
						i, TCPStateToString(mtcp->smap[i].stream));
#ifdef DUMP_STREAM
				DumpStream(mtcp, mtcp->smap[i].stream);
#endif
				mtcp_close(mctx, i);
			}
		}
	}

	ctx->done = 1;

	//pthread_kill(g_thread[mctx->cpu], SIGINT);
	TRACE_INFO("MTCP thread %d joined.\n", mctx->cpu);
	running[mctx->cpu] = FALSE;

	if (mtcp_master == mctx->cpu) {
		for (i = 0; i < num_cpus; i++) {
			if (i != mctx->cpu && running[i]) {
				mtcp_master = i;
				break;
			}
		}
	}

	log_ctx->done = 1;
	ret = write(log_ctx->pair_sp_fd, "F", 1);
	assert(ret == 1);
	UNUSED(ret);
#if defined (PKTDUMP) || (DBGMSG) || (DBGFUNC) || (STREAM)\
	|| (STATE) || (STAT) || (APP) || (EPOLL) || (DUMP_STREAM)
	pthread_join(log_thread[ctx->cpu], NULL);
#endif
	fclose(mtcp->log_fp);
	TRACE_LOG("Log thread %d joined.\n", mctx->cpu);

#if USE_CCP
	destroy_ccp_connection(mtcp);
	close(mtcp->from_ccp);
	close(mtcp->to_ccp);
	TRACE_CCP("CCP thread %d joined.\n", mctx->cpu);
#endif

	if (mtcp->connectq) {
		DestroyStreamQueue(mtcp->connectq);
		mtcp->connectq = NULL;
	}
	if (mtcp->sendq) {
		DestroyStreamQueue(mtcp->sendq);
		mtcp->sendq = NULL;
	}
	if (mtcp->ackq) {
		DestroyStreamQueue(mtcp->ackq);
		mtcp->ackq = NULL;
	}
	if (mtcp->closeq) {
		DestroyStreamQueue(mtcp->closeq);
		mtcp->closeq = NULL;
	}
	if (mtcp->closeq_int) {
		DestroyInternalStreamQueue(mtcp->closeq_int);
		mtcp->closeq_int = NULL;
	}
	if (mtcp->resetq) {
		DestroyStreamQueue(mtcp->resetq);
		mtcp->resetq = NULL;
	}
	if (mtcp->resetq_int) {
		DestroyInternalStreamQueue(mtcp->resetq_int);
		mtcp->resetq_int = NULL;
	}
	if (mtcp->destroyq) {
		DestroyStreamQueue(mtcp->destroyq);
		mtcp->destroyq = NULL;
	}

	DestroyMTCPSender(mtcp->g_sender);
	for (i = 0; i < CONFIG.eths_num; i++) {
		DestroyMTCPSender(mtcp->n_sender[i]);
	}

	MPDestroy(mtcp->rv_pool);
	MPDestroy(mtcp->sv_pool);
	MPDestroy(mtcp->flow_pool);
	
	if (mtcp->ap) {
		DestroyAddressPool(mtcp->ap);
		mtcp->ap = NULL;
	}

	SQ_LOCK_DESTROY(&ctx->connect_lock);
	SQ_LOCK_DESTROY(&ctx->close_lock);
	SQ_LOCK_DESTROY(&ctx->reset_lock);
	SQ_LOCK_DESTROY(&ctx->sendq_lock);
	SQ_LOCK_DESTROY(&ctx->ackq_lock);
	SQ_LOCK_DESTROY(&ctx->destroyq_lock);

	//TRACE_INFO("MTCP thread %d destroyed.\n", mctx->cpu);
	mtcp->iom->destroy_handle(ctx);
	free(ctx);
	if (g_logctx[mctx->cpu]) {
		free(g_logctx[mctx->cpu]);
		g_logctx[mctx->cpu] = NULL;
	}
	g_pctx[mctx->cpu] = NULL;
}
/*----------------------------------------------------------------------------*/
mtcp_sighandler_t 
mtcp_register_signal(int signum, mtcp_sighandler_t handler)
{
	mtcp_sighandler_t prev;

	if (signum == SIGINT) {
		prev = app_signal_handler;
		app_signal_handler = handler;
	} else {
		if ((prev = signal(signum, handler)) == SIG_ERR) {
			perror("signal");
			return SIG_ERR;
		}
	}

	return prev;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_getconf(struct mtcp_conf *conf)
{
	if (!conf)
		return -1;

	conf->num_cores = CONFIG.num_cores;
	conf->max_concurrency = CONFIG.max_concurrency;

	conf->max_num_buffers = CONFIG.max_num_buffers;
	conf->rcvbuf_size = CONFIG.rcvbuf_size;
	conf->sndbuf_size = CONFIG.sndbuf_size;

	conf->tcp_timewait = CONFIG.tcp_timewait;
	conf->tcp_timeout = CONFIG.tcp_timeout;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_setconf(const struct mtcp_conf *conf)
{
	if (!conf)
		return -1;

	if (conf->num_cores > 0)
		CONFIG.num_cores = conf->num_cores;
	if (conf->max_concurrency > 0)
		CONFIG.max_concurrency = conf->max_concurrency;
	if (conf->max_num_buffers > 0)
		CONFIG.max_num_buffers = conf->max_num_buffers;
	if (conf->rcvbuf_size > 0)
		CONFIG.rcvbuf_size = conf->rcvbuf_size;
	if (conf->sndbuf_size > 0)
		CONFIG.sndbuf_size = conf->sndbuf_size;

	if (conf->tcp_timewait > 0)
		CONFIG.tcp_timewait = conf->tcp_timewait;
	if (conf->tcp_timeout > 0)
		CONFIG.tcp_timeout = conf->tcp_timeout;

	TRACE_CONFIG("Configuration updated by mtcp_setconf().\n");
	//PrintConfiguration();

	return 0;
}

/*----------------------------------------------------------------------------*/
int 
mtcp_init(const char *config_file)
{
	int i;
	int ret;

	num_cpus = MIN(MAX_CPUS, GetNumCPUs());

#if 0
	/* TODO: Enable this macro if cross-machine comm. with onvm client/server fails */
	if (num_cpus > 1) {
		TRACE_ERROR("You cannot run mTCP application with more than 1 "
			    "core when you are using ONVM driver\n");
		exit(EXIT_FAILURE);
	}
#endif

	for (i = 0; i < num_cpus; i++) {
		g_mtcp[i] = NULL;
		running[i] = FALSE;
		sigint_cnt[i] = 0;
	}

	ret = LoadConfiguration(config_file);
	if (ret) {
		TRACE_CONFIG("Error occured while loading configuration.\n");
		return -1;
	}
	PrintConfiguration();
        
	printf("CONFIG.num_cores=%d, system cpu-num:%d, num_cores:%d\n", CONFIG.num_cores, GetNumCPUs(), num_cpus);
        assert(num_cpus >= 1);

	for (i = 0; i < CONFIG.eths_num; i++) {
		ap[i] = CreateAddressPool(CONFIG.eths[i].ip_addr, 1);
		if (!ap[i]) {
			TRACE_CONFIG("Error occured while create address pool[%d]\n",
				     i);
			return -1;
		}
	}
	
	PrintInterfaceInfo();

	ret = SetRoutingTable();
	if (ret) {
		TRACE_CONFIG("Error occured while loading routing table.\n");
		return -1;
	}
	PrintRoutingTable();

	LoadARPTable();
	PrintARPTable();

	if (signal(SIGUSR1, HandleSignal) == SIG_ERR) {
		perror("signal, SIGUSR1");
		return -1;
	}
	if (signal(SIGINT, HandleSignal) == SIG_ERR) {
		perror("signal, SIGINT");
		return -1;
	}
	app_signal_handler = NULL;

	/* load system-wide io module specs */
	current_iomodule_func->load_module();

	return 0;
}
/*----------------------------------------------------------------------------*/
void 
mtcp_destroy()
{
	int i;
#ifndef DISABLE_DPDK
	int master = rte_get_main_lcore();
#endif
	/* wait until all threads are closed */
	for (i = 0; i < num_cpus; i++) {
		if (running[i]) {
#ifndef DISABLE_DPDK
			if (master != i)
				rte_eal_wait_lcore(i);
			else
#endif
			{
				pthread_join(g_thread[i], NULL);
			}
		}
	}

	for (i = 0; i < CONFIG.eths_num; i++)
		DestroyAddressPool(ap[i]);

#ifndef DISABLE_DPDK
	mpz_clear(CONFIG._cpumask);
#endif

#ifdef ENABLE_ONVM
	onvm_nflib_stop(CONFIG.nf_local_ctx);
#endif

	TRACE_INFO("All MTCP threads are joined.\n");
}
/*----------------------------------------------------------------------------*/
