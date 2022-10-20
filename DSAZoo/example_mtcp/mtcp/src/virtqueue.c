#include <stdint.h>
#include <malloc.h>
#include <string.h>

#define smp_wmb __sync_synchronize

#include "virtqueue.h"

const size_t BUFF_SZ = 1500;
const size_t ALIGNMENT = 128;

struct virtqueue* init_virtqueue(int queue_size, int desc_buf_size)
{
    struct virtqueue * pvq = memalign(ALIGNMENT, sizeof(struct virtqueue));
	if (!pvq)
    {
        printf( "Error allocation init_virtqueue.\n");
        return NULL;
    }

    // alloc vring
    size_t size = vring_size(queue_size, ALIGNMENT);
    uint8_t *pvring = memalign(ALIGNMENT, size);
    if (!pvring)
    {
        printf( "Error allocation vring.\n");
	free(pvq);
        return NULL;
    }

    vring_init(&pvq->ring, queue_size, pvring, ALIGNMENT);
    pvq->vq_ring_virt_mem = pvring;

    // alloc buffers in advance
    // size = queue_size * desc_buf_size;
    // uint8_t *pbuf = memalign(ALIGNMENT, size);
    // if (!pbuf)
    // {
    //     printf( "Error allocation desc buffers.\n");
    //     return NULL;
    // }
    
    // vring_init_desc(&pvq->ring, pbuf, desc_buf_size);
    // pvq->vq_desc_buf_virt_mem = pbuf;

    // init virtqueue variables
    pvq->vq_used_cons_idx = 0; /**< last consumed descriptor */
	pvq->vq_nentries = queue_size;  /**< vring desc numbers */
	pvq->vq_free_cnt = queue_size;  /**< num of desc available */
	pvq->vq_avail_idx = 0; /**< sync until needed */
	pvq->vq_free_thresh = 0; /**< free threshold */

	/**
	 * Head of the free chain in the descriptor table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 */
	pvq->vq_desc_head_idx = 0;
	pvq->vq_desc_tail_idx = 0;
	//uint16_t  vq_queue_index;   /**< PCI queue index */

	//void *vq_ring_virt_mem;  /**< linear address of vring*/
	pvq->vq_ring_size = queue_size;
    pvq->vhost_vq_avail_idx = 0;
    pvq->vhost_vq_used_cons_idx = 0;
    pvq->vhost_vq_used_cons_len = 0;

    //malloc memory for buffs
    for(int i = 0; i < queue_size; i ++){
    	pvq->ring.desc[i].addr = (uint64_t)malloc(BUFF_SZ);
	pvq->ring.desc[i].len = BUFF_SZ;
    }

    return pvq;
}

int deinit_virtqueue(void* ptr)
{
    if(ptr == NULL) return -1;
    struct virtqueue * vqp = (struct virtqueue *)ptr;
    if(vqp == NULL){
    	return -1;
    }
    int i;	
    for(i = 0; i < vqp->vq_nentries; i++){
    	free((void *)vqp->ring.desc[i].addr);
    }


    // free vring
    if(vqp->vq_ring_virt_mem){
        free(vqp->vq_ring_virt_mem);
        vqp->vq_ring_virt_mem = NULL;
    }

    // free virtqueue
    if(vqp){
        free(vqp);
        vqp = NULL;
    }
    return 0;
}

int virtqueue_add_buf(char* p_data_send, int len, struct virtqueue * virtqueue)
{
    int ret = 0;
    if(virtqueue->vq_avail_idx >= virtqueue->vq_used_cons_idx){
        virtqueue->vq_free_cnt = virtqueue->vq_nentries - (virtqueue->vq_avail_idx - virtqueue->vq_used_cons_idx);	
    }
    else{
        virtqueue->vq_free_cnt = virtqueue->vq_nentries - (virtqueue->vq_used_cons_idx - virtqueue->vq_avail_idx);
    }
    if(virtqueue->vq_free_cnt == 0){
        virtqueue->vq_used_cons_idx = 0; /**< last consumed descriptor */
	virtqueue->vq_free_cnt = virtqueue->vq_nentries;  /**< num of desc available */
	virtqueue->vq_avail_idx = 0; /**< sync until needed */
    }


    virtqueue->ring.desc[virtqueue->vq_avail_idx].addr = (uint64_t)p_data_send;
    virtqueue->ring.desc[virtqueue->vq_avail_idx].len = len;

    smp_wmb();
    virtqueue->vq_avail_idx = (virtqueue->vq_avail_idx + 1) % virtqueue->vq_nentries;

    return 0;
}

int virtqueue_add_buf2(char* p_data_send, int len, struct virtqueue * virtqueue)
{
	if(p_data_send == NULL) return -1;
	if(virtqueue->vq_avail_idx >= virtqueue->vq_used_cons_idx){
		virtqueue->vq_free_cnt = virtqueue->vq_nentries - (virtqueue->vq_avail_idx - virtqueue->vq_used_cons_idx);
	}
	else{
		virtqueue->vq_free_cnt = virtqueue->vq_nentries - (virtqueue->vq_used_cons_idx - virtqueue->vq_avail_idx);
	}
	if(virtqueue->vq_free_cnt == 0){
		virtqueue->vq_used_cons_idx = 0; /**< last consumed descriptor */
		virtqueue->vq_free_cnt = virtqueue->vq_nentries;  /**< num of desc available */
		virtqueue->vq_avail_idx = 0; /**< sync until needed */
	}


	//virtqueue->ring.desc[virtqueue->vq_avail_idx].addr = (uint64_t)p_data_send;
	//virtqueue->ring.desc[virtqueue->vq_avail_idx].len = len;
	memcpy((void *)virtqueue->ring.desc[virtqueue->vq_avail_idx].addr, p_data_send, len);

	smp_wmb();
	virtqueue->vq_avail_idx = (virtqueue->vq_avail_idx + 1) % virtqueue->vq_nentries;
	return 0;
}


int virtqueue_get_buf(char** p_data_recv, int* len, struct virtqueue * virtqueue)
{
    int ret = 1;
    if(virtqueue->vq_avail_idx >= virtqueue->vq_used_cons_idx){
        // update vq_used_cons_idx from vring used
        // start---vq_used_cons_idx---"ring.used->idx"---vq_avail_idx---end
        if(virtqueue->ring.used->idx > virtqueue->vq_used_cons_idx){
            *p_data_recv = (char*)virtqueue->ring.desc[virtqueue->vq_used_cons_idx].addr;
            *len = virtqueue->ring.desc[virtqueue->vq_used_cons_idx].len;
            virtqueue->vq_used_cons_idx = (virtqueue->vq_used_cons_idx + 1) % virtqueue->vq_nentries;
            ret = 0;
        }
    }
    else{
        // update vq_used_cons_idx from vring used
        // start---vq_avail_idx---vq_used_cons_idx---"ring.used->idx"---end
        if(virtqueue->ring.used->idx > virtqueue->vq_used_cons_idx && 
           virtqueue->ring.used->idx > virtqueue->vq_avail_idx){
            *p_data_recv = (char*)virtqueue->ring.desc[virtqueue->vq_used_cons_idx].addr;
            *len = virtqueue->ring.desc[virtqueue->vq_used_cons_idx].len;
            virtqueue->vq_used_cons_idx = (virtqueue->vq_used_cons_idx + 1) % virtqueue->vq_nentries;
            ret = 0;
        }
        // start---"ring.used->idx"---vq_avail_idx---vq_used_cons_idx---end
        else if(virtqueue->ring.used->idx <= virtqueue->vq_avail_idx){
            *p_data_recv = (char*)virtqueue->ring.desc[virtqueue->vq_used_cons_idx].addr;
            *len = virtqueue->ring.desc[virtqueue->vq_used_cons_idx].len;
            virtqueue->vq_used_cons_idx = (virtqueue->vq_used_cons_idx + 1) % virtqueue->vq_nentries;
            ret = 0;
        }
    }

    //printf("virtqueue_get_buf: \n");

    return ret;
}

int virtqueue_kick(struct virtqueue * virtqueue)
{
    if(virtqueue->vq_avail_idx != virtqueue->ring.avail->idx){
        virtqueue->ring.avail->idx = virtqueue->vq_avail_idx;
    }


    return 0;
}

int vhost_virtqueue_done(uint16_t idx, struct virtqueue * virtqueue)
{
    //if(vring_is_empty(&virtqueue->ring)){
    //    return 0;
    //}

    //if(virtqueue->ring.avail->idx > virtqueue->ring.used->idx){
        virtqueue->ring.used->ring[virtqueue->ring.used->idx].id = idx;
        virtqueue->ring.used->ring[virtqueue->ring.used->idx].len = virtqueue->ring.desc[idx].len;
        virtqueue->ring.used->idx = (virtqueue->ring.used->idx + 1) % virtqueue->vq_nentries;
        //*p_data_recv = (char*)virtqueue->ring.desc[idx].addr;
        //*len = virtqueue->ring.desc[idx].len;
    //}

            

        //virtqueue->vhost_vq_used_cons_idx = idx_tmp;
        //virtqueue->vhost_vq_used_cons_len = virtqueue->ring.desc[idx_tmp].len;
    
//    printf("vhost_virtqueue_done: vr.avail.idx=%d, vr.used.idx=%d\n",
//        virtqueue->ring.avail->idx,
//        virtqueue->ring.used->idx);

    return 0;
}

int vhost_get_req(char** p_data_recv, int* len, uint16_t* idx, struct virtqueue * virtqueue)
{
    if(virtqueue->vq_avail_idx == virtqueue->vq_used_cons_idx){
    	return -1;
    }

    uint16_t idx_tmp = virtqueue->vq_used_cons_idx;
    *p_data_recv = (char*)virtqueue->ring.desc[idx_tmp].addr;
    *len = virtqueue->ring.desc[idx_tmp].len;
    *idx = idx_tmp;

    smp_wmb();
    virtqueue->vq_used_cons_idx = (virtqueue->vq_used_cons_idx + 1) % virtqueue->vq_nentries;
    return 0;
}

int init_virtio(struct queue_context *pqctx)
{
    pqctx->tx_virtqueue = init_virtqueue(pqctx->tx_queue_size, pqctx->tx_desc_buf_size);
	if(NULL == pqctx->tx_virtqueue){
		printf( "Error init_virtqueue.\n");
        return -1;
	}

    pqctx->rx_virtqueue = init_virtqueue(pqctx->rx_queue_size, pqctx->rx_desc_buf_size);
	if(NULL == pqctx->rx_virtqueue){
		printf( "Error init_virtqueue.\n");
        return -1;
	}

    return 0;
}

int deinit_virtio(struct queue_context *pqctx)
{
    // deinit virtqueue
	if(pqctx->tx_virtqueue){
		deinit_virtqueue(pqctx->tx_virtqueue);
	}

	if(pqctx->rx_virtqueue){
		deinit_virtqueue(pqctx->rx_virtqueue);
	}

    return 0;
}
