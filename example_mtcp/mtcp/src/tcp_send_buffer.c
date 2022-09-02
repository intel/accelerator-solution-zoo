#include <string.h>

#include "memory_mgt.h"
#include "debug.h"
#include "tcp_send_buffer.h"
#include "tcp_sb_queue.h"
#ifdef DSA_ENABLE
#include "dsa.h"
#endif
#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
/*----------------------------------------------------------------------------*/
struct sb_manager
{
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;
	mem_pool_t mp;
	sb_queue_t freeq;

} sb_manager;
/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm)
{
	return sbm->cur_num;
}
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum)
{
	sb_manager_t sbm = (sb_manager_t)calloc(1, sizeof(sb_manager));
	if (!sbm) {
		TRACE_ERROR("SBManagerCreate() failed. %s\n", strerror(errno));
		return NULL;
	}

	sbm->chunk_size = chunk_size;
	sbm->cnum = cnum;
#if !defined(DISABLE_DPDK) && !defined(ENABLE_ONVM)
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	sprintf(pool_name, "sbm_pool_%d", mtcp->ctx->cpu);
	sbm->mp = (mem_pool_t)MPCreate(pool_name, chunk_size, (uint64_t)chunk_size * cnum);	
#else
	sbm->mp = (mem_pool_t)MPCreate(chunk_size, (uint64_t)chunk_size * cnum);
#endif
	if (!sbm->mp) {
		TRACE_ERROR("Failed to create mem pool for sb.\n");
		free(sbm);
		return NULL;
	}

	sbm->freeq = CreateSBQueue(cnum);
	if (!sbm->freeq) {
		TRACE_ERROR("Failed to create free buffer queue.\n");
		MPDestroy(sbm->mp);
		free(sbm);
		return NULL;
	}

	return sbm;
}
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq)
{
	struct tcp_send_buffer *buf;

	/* first try dequeue from free buffer queue */
	buf = SBDequeue(sbm->freeq);
	if (!buf) {
		buf = (struct tcp_send_buffer *)malloc(sizeof(struct tcp_send_buffer));
		if (!buf) {
			perror("malloc() for buf");
			return NULL;
		}
		buf->data = MPAllocateChunk(sbm->mp);
		if (!buf->data) {
			TRACE_ERROR("Failed to fetch memory chunk for data.\n");
			free(buf);
			return NULL;
		}
		sbm->cur_num++;
	}

	buf->head = buf->data;

	buf->head_off = buf->tail_off = 0;
	buf->len = buf->cum_len = 0;
	buf->size = sbm->chunk_size;

	buf->init_seq = buf->head_seq = init_seq;
	
	return buf;
}
/*----------------------------------------------------------------------------*/
#if 0
static void 
SBFreeInternal(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
	if (!buf)
		return;

	if (buf->data) {
		MPFreeChunk(sbm->mp, buf->data);
		buf->data = NULL;
	}

	sbm->cur_num--;
	free(buf);
}
#endif
/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
	if (!buf)
		return;

	SBEnqueue(sbm->freeq, buf);
}
/*----------------------------------------------------------------------------*/
inline unsigned long rdtsc(void)
{
	uint32_t a, d;

	asm volatile("rdtsc" : "=a"(a), "=d"(d));
	return ((uint64_t)d << 32) | (uint64_t)a;
}


static inline void memcpy_vector_cpu(unsigned char **src_arr, unsigned char **dst_arr, int nb_bufs,  uint32_t buf_len)
{
        uint32_t j;
        for (j = 0; j < nb_bufs; j++) {
                memcpy(dst_arr[j], src_arr[j], buf_len);
        }
}

size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	/* if no space, return -2 */
	to_put = MIN(len, buf->size - buf->len);
	if (to_put < len) {
		return -2;
	}
	unsigned long start = rdtsc();
	if (buf->tail_off + to_put <= buf->size) {
		/* if the data fit into the buffer, copy it */
		memcpy(buf->data + buf->tail_off, data, to_put);
		buf->tail_off += to_put;
	} else {
		/* if buffer overflows, move the existing payload and merge */
		printf("memmove \n");
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		memcpy(buf->head + buf->len, data, to_put);
		buf->tail_off = buf->len + to_put;
	}
	static unsigned cnt;
	static unsigned time;
	time += (rdtsc() - start);
	if (++cnt % 10000 == 0)
	{
		printf("cpu memcpy len :%zu cost %ld cycles\n", to_put, rdtsc() - start);
		time = 0;
	}
	buf->len += to_put;
	buf->cum_len += to_put;

	return to_put;
}

extern size_t tail_off_tmp;
extern size_t len_tmp;

size_t 
SBPut_async(mctx_t mctx, sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	/* if no space, return -2 */
	to_put = MIN(len, buf->size - buf->len);
	if (to_put < len) {
		return -2;
	}

	if (buf->tail_off + to_put <= buf->size) {
		/* if the data fit into the buffer, copy it */
		//submit dsa copy data task and return, without wait complete
		int rc = dsa_memcpy_async_submit(mctx->dsa, data, buf->data + buf->tail_off, to_put);
		if(rc != 0x0){
			printf("dsa memcpy failed!\n");
			return -2;
			}
		tail_off_tmp = buf->tail_off + to_put; //when dsa task complete, update tail off
	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		printf("memmove\n");
		buf->head = buf->data;
		buf->head_off = 0;
		buf->tail_off = buf->len;
		int rc = dsa_memcpy_async_submit(mctx->dsa, data, buf->head + buf->len, to_put);
		if(rc != 0x0){
			printf("dsa memcpy failed!\n");
			return -2;
		}
		tail_off_tmp = buf->len + to_put;
	}
	len_tmp = to_put;
	return to_put;
}

size_t 
SBPut_dsa(mctx_t mctx, sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	/* if no space, return -2 */
	to_put = MIN(len, buf->size - buf->len);
	if (to_put < len) {
		return -2;
	}
	unsigned long start = rdtsc();
	if (buf->tail_off + to_put <= buf->size) {
		/* if the data fit into the buffer, copy it */
		#ifdef DSA_ENABLE
			int rc = dsa_memcpy_single(mctx->dsa, data, buf->data + buf->tail_off, to_put);
			if(rc != 0x0){
				printf("dsa memcpy failed!\n");
				return -2;
			}
		#else
			memcpy(buf->data + buf->tail_off, data, to_put);
		#endif
		//printf("send buf dsa copy data content: %.*s\n", to_put, buf->data + buf->tail_off);
		buf->tail_off += to_put;
	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		#ifdef DSA_ENABLE
		int rc = dsa_memcpy_single(mctx->dsa, data, buf->head + buf->len, to_put);
		if(rc != 0x0){
			printf("dsa memcpy failed!\n");
			return -2;
		}
		#else
			memcpy(buf->head + buf->len, data, to_put);
		#endif
		//printf("send buf dsa copy data content: %.*s\n", to_put, buf->head + buf->len);
		buf->tail_off = buf->len + to_put;
	}
	static unsigned cnt;
	static unsigned time;
	time += (rdtsc() - start);
        if (cnt++ % 10000 == 0)
        {	
                printf("dsa memcpy len :%zu cost %u cycles\n", to_put, time/10000);
		time = 0;
        }

	buf->len += to_put;
	buf->cum_len += to_put;

	return to_put;
}

/*----------------------------------------------------------------------------*/


int use_dsa = 0;

size_t
SBPut_vector(mctx_t mctx, sb_manager_t sbm, struct tcp_send_buffer *buf, const struct iovec *iov, int numIOV, int len)
{
	size_t to_put;
	int i;
	unsigned long buf_size;
	unsigned char *sbf_arr[512];
	unsigned char *dbf_arr[512];
	unsigned char *start;
	unsigned long begin, end;

	static int cost_cycles = 0;
	static int count = 0;
	int rc = 0x0;
	
	if (len <= 0)
		return 0;

	/* if no space, return -2 */
	to_put = MIN(len, buf->size - buf->len);
	if (to_put < len) {
		return -2;
	}

	buf_size = iov[0].iov_len;

	if (buf->tail_off + to_put <= buf->size) {
		/* if the data fit into the buffer, copy it */
		start = buf->data + buf->tail_off;
		for(i=0; i<numIOV; i++) {
			sbf_arr[i] = iov[i].iov_base;
			dbf_arr[i] = start + buf_size*i;
		//	printf("sbf_arr %d: %x, dbf_arr %d: %x\n", i, sbf_arr[i], i, dbf_arr[i]);

		}
		begin = rdtsc();
	        if(use_dsa) {	
			rc = dsa_memcpy_vector(mctx->dsa, sbf_arr, dbf_arr, numIOV, buf_size);
		} else {
			memcpy_vector_cpu(sbf_arr, dbf_arr, numIOV, buf_size);
		}
		end = rdtsc();
		if(rc != 0x0){
			printf("dsa memcpy failed!\n");
			return -2;
		}

		cost_cycles += (end - begin);
		count ++;
		if(count == 100) {
			if(use_dsa) {
				printf("dsa memcpy vector copy %d size cost %d cycles\n", len, cost_cycles/100);
			} else {
				printf("cpu memcpy copy %d size cost %d cycles\n", len, cost_cycles/100);
			}
			count = 0;
			cost_cycles = 0;
		}
		//printf("send buf dsa copy data content: %.*s\n", to_put, buf->data + buf->tail_off);
		buf->tail_off += to_put;
	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		start = buf->data;
		for(i=0; i<numIOV; i++) {
			sbf_arr[i] = iov[i].iov_base;
			dbf_arr[i] = start + buf_size*i;
		//	printf("sbf_arr %d: %x, dbf_arr %d: %x\n", i, sbf_arr[i], i, dbf_arr[i]);
		}
		begin = rdtsc();
		if(use_dsa) {
                        rc = dsa_memcpy_vector(mctx->dsa, sbf_arr, dbf_arr, numIOV, buf_size);
                } else {
                        memcpy_vector_cpu(sbf_arr, dbf_arr, numIOV, buf_size);
                }
		end = rdtsc();
		if(rc != 0x0){
			printf("dsa memcpy failed!\n");
			return -2;
		}
		cost_cycles += (end - begin);
		count ++;
		if(count == 100) {
			if(use_dsa) {
				printf("dsa memcpy vector copy %d size cost %d cycles\n", len, cost_cycles/100);
			} else {
				printf("cpu memcpy copy %d size cost %d cycles\n", len, cost_cycles/100);
			}
			count = 0;
			cost_cycles = 0;
		}
		//printf("send buf dsa copy data content: %.*s\n", to_put, buf->head + buf->len);
		buf->tail_off = buf->len + to_put;
	}

	buf->len += to_put;
	buf->cum_len += to_put;

	return to_put;
}
/*----------------------------------------------------------------------------*/
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len)
{
	size_t to_remove;

	if (len <= 0)
		return 0;

	to_remove = MIN(len, buf->len);
	if (to_remove <= 0) {
		return -2;
	}

	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;

	/* if buffer is empty, move the head to 0 */
	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}
/*---------------------------------------------------------------------------*/
