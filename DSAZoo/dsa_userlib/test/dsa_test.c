// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <malloc.h>
#include "dsa.h"

#define DSA_TEST_SIZE 20000
#define SHARED 1
#define DEDICATED 0

static void usage(void)
{
	printf("<app_name> [options]\n"
	"-w <wq_type> ; 0=dedicated, 1=shared\n"
	"-l <length>  ; total test buffer size\n"
	"-f <test_flags> ; 0x1: block-on-fault\n"
	"                ; 0x4: reserved\n"
	"                ; 0x8: prefault buffers\n"
	"-o <opcode>     ; opcode, same value as in DSA spec\n"
	"-b <opcode> ; if batch opcode, opcode in the batch\n"
	"-c <batch_size> ; if batch opcode, number of descriptors for batch\n"
	"-t <ms timeout> ; ms to wait for descs to complete\n"
	"-v              ; verbose\n"
	"-h              ; print this message\n");
}

static inline unsigned long rdtsc(void)
{
        uint32_t a, d;

        asm volatile("rdtsc" : "=a"(a), "=d"(d));
        return ((uint64_t)d << 32) | (uint64_t)a;
}

static int test_batch(struct dsa_context *ctx, size_t buf_size,
		int tflags, uint32_t bopcode, unsigned int bsize)
{
	unsigned long dflags;
	int rc = 0;

	info("batch: len %#lx tflags %#x bopcode %#x batch_no %d\n",
			buf_size, tflags, bopcode, bsize);

	if (bopcode == DSA_OPCODE_BATCH) {
		err("Can't have batch op inside batch op\n");
		return -EINVAL;
	}

	ctx->is_batch = 1;

	rc = alloc_batch_task(ctx, bsize);
	if (rc != DSA_STATUS_OK)
		return rc;

	dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tflags & TEST_FLAGS_BOF) && ctx->bof)
		dflags |= IDXD_OP_FLAG_BOF;

	rc = init_batch_task(ctx->batch_task, bsize, tflags, bopcode,
			buf_size, dflags);
	if (rc != DSA_STATUS_OK)
		return rc;

	switch (bopcode) {
	case DSA_OPCODE_MEMMOVE:
		dsa_prep_batch_memcpy(ctx->batch_task);
		break;

	case DSA_OPCODE_MEMFILL:
		dsa_prep_batch_memfill(ctx->batch_task);
		break;

	case DSA_OPCODE_COMPARE:
		dsa_prep_batch_compare(ctx->batch_task);
		break;

	case DSA_OPCODE_COMPVAL:
		dsa_prep_batch_compval(ctx->batch_task);
		break;
	case DSA_OPCODE_DUALCAST:
		dsa_prep_batch_dualcast(ctx->batch_task);
		break;
	default:
		err("Unsupported op %#x\n", bopcode);
		return -EINVAL;
	}

	dsa_prep_batch(ctx->batch_task, dflags);
	dump_sub_desc(ctx->batch_task);
	dsa_desc_submit(ctx, ctx->batch_task->core_task->desc);

	rc = dsa_wait_batch(ctx);
	if (rc != DSA_STATUS_OK) {
		err("batch failed stat %d\n", rc);
		rc = -ENXIO;
	}

	rc = batch_result_verify(ctx->batch_task, dflags & IDXD_OP_FLAG_BOF);

	return rc;
}

int main(int argc, char *argv[])
{
	struct dsa_context *dsa;
	int rc = 0;
	unsigned long buf_size = DSA_TEST_SIZE;
	int wq_type = SHARED;
	int dev_id = -1, wq_id = -1; 
	int opcode = DSA_OPCODE_MEMMOVE;
	int bopcode = DSA_OPCODE_MEMMOVE;
	int tflags = TEST_FLAGS_BOF;
	int opt;
	unsigned int bsize = 0;
	unsigned long start, end;

	while ((opt = getopt(argc, argv, "w:d:q:l:f:o:b:c:t:p:vh")) != -1) {
		switch (opt) {
		case 'w':
			wq_type = atoi(optarg);
			break;
		case 'd':
			dev_id = atoi(optarg);
			break;
		case 'q':
			wq_id = atoi(optarg);
			break;
		case 'l':
			buf_size = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			tflags = strtoul(optarg, NULL, 0);
			break;
		case 'o':
			opcode = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			bopcode = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			bsize = strtoul(optarg, NULL, 0);
			break;
		case 't':
			ms_timeout = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			debug_logging = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			break;
		}
	}

	dsa = dsa_init();

	if (dsa == NULL)
		return -ENOMEM;

	rc = dsa_alloc_raw(dsa, dev_id, wq_id, wq_type);
	if (rc < 0)
		return -ENOMEM;

	if (buf_size > dsa->max_xfer_size) {
		err("invalid transfer size: %lu\n", buf_size);
		return -EINVAL;
	}

	rc = alloc_task(dsa);
	if(rc != DSA_STATUS_OK) {
		printf("alloc task failed!\n");
		goto clean_dsa;
	}
	//struct task *t = dsa->single_task;;
	
	unsigned char *sbuff = memalign(64, buf_size);
	if(sbuff == NULL)
	{
		printf("alloc memory sbuff failed!\n");
		goto clean_dsa;
	}
	unsigned char *dbuff = memalign(4096, buf_size);
        if(dbuff == NULL){
                printf("alloc memory dbuff failed!\n");
		free(sbuff);
                goto clean_dsa;
        }
	memset(sbuff, 0x88, buf_size);
	memset(dbuff, 0, buf_size);

	start = rdtsc();

	rc = dsa_memcpy_single(dsa, sbuff, dbuff, buf_size);
	if(rc != DSA_STATUS_OK){
		printf("dsa memcpy failed!\n");
		goto clean_mem;
	}
	
	end = rdtsc();

	printf("dsa memcpy cost cpu cycles: %#ld\n", end - start);

	//finally, we verfiy the result
	printf("dst buff content:%#hhx, %#hhx, %#hhx \n", dbuff[0], dbuff[1], dbuff[buf_size - 2]);
	int i; 
	for(i = 0; i < buf_size; i++) {
		if(dbuff[i] != 0x88) {
			printf("verify dst buff failed!\n");
			goto clean_mem;
		}
	}
	printf("verify dst buff pass, test dsa pass.\n");

clean_mem:	
	free(dbuff);
	free(sbuff);
clean_dsa:
	dsa_free(dsa);
	return 0;

}
