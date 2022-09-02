
#ifndef _VIRTQUEUE_H_
#define _VIRTQUEUE_H_

#include <stdint.h>

//#include <rte_atomic.h>
//#include <rte_memory.h>
//#include <rte_mempool.h>
//#include <rte_net.h>

//#include "virtio.h"
#include "virtio_ring.h"
//#include "virtio_logs.h"
//#include "virtio_rxtx.h"

//#include "virtio_ring.h"
struct virtqueue {
    struct vring ring;
	uint16_t vq_used_cons_idx; /**< last consumed descriptor */
	uint16_t vq_nentries;  /**< vring desc numbers */
	uint16_t vq_free_cnt;  /**< num of desc available */
	uint16_t vq_avail_idx; /**< sync until needed */
	uint16_t vq_free_thresh; /**< free threshold */

	/**
	 * Head of the free chain in the descriptor table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 */
	uint16_t  vq_desc_head_idx;
	uint16_t  vq_desc_tail_idx;
	uint16_t  vq_queue_index;   /**< PCI queue index */

	void *vq_ring_virt_mem;  /**< linear address of vring*/
	unsigned int vq_ring_size;
	uint16_t mbuf_addr_offset;

	rte_iova_t vq_ring_mem; /**< physical address of vring,
	                         * or virtual address for virtio_user. */

	uint16_t  *notify_addr;
	struct rte_mbuf **sw_ring;  /**< RX software ring. */
	//struct vq_desc_extra vq_descx[0];

	void *vq_desc_buf_virt_mem;  /**< linear address of vring*/
	uint16_t vhost_vq_used_cons_idx; /**< vhost last consumed descriptor */
	int vhost_vq_used_cons_len;
    uint16_t vhost_vq_avail_idx;

};

struct queue_context
{
	// tx ctx
	int tx_queue_size;
	int tx_desc_buf_size;
	void* tx_virtqueue;

	// rx ctx
	int rx_queue_size;
	int rx_desc_buf_size;
	void* rx_virtqueue;

	// common context
	// int socket_id;
	//mctx_t mctx;

	volatile int stop_signal;
};

struct virtqueue* init_virtqueue(int queue_size, int desc_buf_size);

int deinit_virtqueue(void* ptr);

int virtqueue_add_buf(char* p_data_send, int len, struct virtqueue * virtqueue);
int virtqueue_add_buf2(char* p_data_send, int len, struct virtqueue * virtqueue);

int virtqueue_get_buf(char** p_data_recv, int* len, struct virtqueue * virtqueue);

int virtqueue_kick(struct virtqueue * virtqueue);

int vhost_virtqueue_done(uint16_t idx, struct virtqueue * virtqueue);

int vhost_get_req(char** p_data_recv, int* len, uint16_t* idx, struct virtqueue * virtqueue);

int init_virtio(struct queue_context *pqctx);

int deinit_virtio(struct queue_context *pqctx);

#endif /* _VIRTQUEUE_H_ */
