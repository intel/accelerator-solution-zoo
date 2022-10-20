// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <malloc.h>
#include <sched.h>
#include "dsa.h"

#define DSA_TEST_SIZE 20000
#define SHARED 1
#define DEDICATED 0

unsigned long buf_size = DSA_TEST_SIZE;
uint32_t nb_bufs = 1;

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

int cpu_pin(uint32_t cpu)
{
        cpu_set_t *cpuset;
        size_t cpusetsize;

        cpusetsize = CPU_ALLOC_SIZE(get_nprocs());
        cpuset = CPU_ALLOC(get_nprocs());
        CPU_ZERO_S(cpusetsize, cpuset);
        CPU_SET_S(cpu, cpusetsize, cpuset);

        pthread_setaffinity_np(pthread_self(), cpusetsize, cpuset);

        CPU_FREE(cpuset);

        return 0;
}

static void *thread_func(void *arg)
{
	struct percpu_tasks *ipt = (struct percpu_tasks *)arg;
	int rc = -1, i; 
	unsigned long start, end;
	unsigned char *sbf_arr[nb_bufs];
	unsigned char *dbf_arr[nb_bufs];

	if(ipt == NULL) {
		printf("Empty percpu_tasks instance\n");
		return NULL;
	}
	int cpuid = ipt->cpuid;

	/*skip cpu 0, user cpu 5 as start-step. 
	 If don't call cpu_pin will also works, scheduler will help to select a cpu*/
	//cpu_pin(cpuid + 5);
	/*
	struct sched_param param;
	param.sched_priority = 80;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
	*/
	struct dsa_context *ctx = ipt->dsa_ctx;
	if(ctx == NULL) {
		printf("invalid dsa oontext\n");
		return NULL;
	}
	rc = alloc_thread_stasks(ctx, cpuid);
	
	for(i = 0; i < nb_bufs; i++) {
		sbf_arr[i] = memalign(64, buf_size);
		dbf_arr[i] = memalign(4096, buf_size);

		if(sbf_arr[i] == NULL || dbf_arr[i] == NULL){
                	printf("alloc memory buff failed!\n");
        		return NULL;
		}

		memset(sbf_arr[i], 0x99 + i, buf_size);
		memset(dbf_arr[i], 0, buf_size);
	}
        //start = rdtsc();

	/*test async submit vector*/
        rc = dsa_memcpy_async_submit_vector(ipt, sbf_arr, dbf_arr, nb_bufs / 2,  buf_size);
        if(rc != DSA_STATUS_OK){
                printf("dsa memcpy failed!\n");
        }

	int cn = 0;
	while(cn < nb_bufs / 2){
	
		rc = dsa_memcpy_check_comp(ipt, nb_bufs / 2);
		if(rc > 0 ){
			cn += rc;
		}
		else {
			usleep(1);
		}
	}

	//finally, we verfiy the result
	for(i = 0; i < nb_bufs/2; i++) {
		int j;
		for(j = 0; j < buf_size; j++) {
			if(dbf_arr[i][j] != 0x99 + i) {
				printf("Position %d-%d value failed, value is : %x \n", i, j, dbf_arr[i][j]);
				printf("verify dst buff failed!\n");
				goto free_mem;
			}
		}
		memset(dbf_arr[i], 0, buf_size);
	}
	printf("verify dst buff pass, async submit vector test dsa pass.\n");

	/*test async submit*/
	for(i = 0; i < nb_bufs/2; i++) {
		rc = dsa_memcpy_async_submit1(ipt, sbf_arr[i], dbf_arr[i], buf_size);
		if(rc != DSA_STATUS_OK) {
			goto free_mem;
		}
	}
	cn = 0;
        while(cn < nb_bufs / 2){

                rc = dsa_memcpy_check_comp(ipt, nb_bufs / 2);
                if(rc > 0 ){
                        cn += rc;
                }
                else {
                        usleep(1);
                }
        }

        //finally, we verfiy the result
        for(i = 0; i < nb_bufs/2; i++) {
                int j;
                for(j = 0; j < buf_size; j++) {
                        if(dbf_arr[i][j] != 0x99 + i) {
                                printf("Position %d-%d value failed, value is : %x \n", i, j, dbf_arr[i][j]);
                                printf("verify dst buff failed!\n");
                                goto free_mem;
                        }
                }
                memset(dbf_arr[i], 0, buf_size);
        }
	

	printf("verify dst buff pass, test dsa pass.\n");
	return NULL;

free_mem:
	for(i = 0; i < nb_bufs; i++){
		free(sbf_arr[i]);
		free(dbf_arr[i]);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct dsa_context *dsa;
	int rc = 0;
	//unsigned long buf_size = DSA_TEST_SIZE;
	int wq_type = SHARED;
	int opcode = DSA_OPCODE_MEMMOVE;
	int bopcode = DSA_OPCODE_MEMMOVE;
	int tflags = TEST_FLAGS_BOF;
	int ncpu = 0;
	int opt;
	unsigned int bsize = 0;
	int i;

	while ((opt = getopt(argc, argv, "w:l:f:o:b:c:t:p:n:vh")) != -1) {
		switch (opt) {
		case 'w':
			wq_type = atoi(optarg);
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
		case 'p':
                        ncpu = strtoul(optarg, NULL, 0);
                        break;
		case 'n':
                        nb_bufs = strtoul(optarg, NULL, 0);
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

	rc = dsa_alloc(dsa, wq_type);
	if (rc < 0)
		return -ENOMEM;

	if (buf_size > dsa->max_xfer_size) {
		err("invalid transfer size: %lu\n", buf_size);
		return -EINVAL;
	}
	if(ncpu == 0) {
		ncpu = 1;
	}
	dsa->ncpu = ncpu;
	//rc = alloc_task(dsa);
	rc = alloc_percpu_tasks(dsa);
	if(rc != DSA_STATUS_OK) {
		printf("alloc task failed!\n");
		goto clean_dsa;
	}
	//struct task *t = dsa->single_task;;
	pthread_t tid[MAX_USE_CPUS];
	for(i = 0; i < ncpu; i++) {
		pthread_mutex_lock(&dsa->tlock);
		struct percpu_tasks *ipt = &(dsa->pct[i]);
		
		if(dsa->nth < 1) {
			printf("No valuable percpu task slot");
			pthread_mutex_unlock(&dsa->tlock);
                        goto clean_dsa;
		}

		dsa->nth--;
		ipt->cpuid = i;
		rc = pthread_create(&tid[i], NULL, thread_func, ipt);
		if(rc) {
			printf("create thread failed\n");
			pthread_mutex_unlock(&dsa->tlock);
			goto clean_dsa;
		}
		pthread_mutex_unlock(&dsa->tlock);
	}

	for(i = 0; i < ncpu; i++) {
		rc = pthread_join(tid[i], NULL);
		if(rc != 0)
		{
			perror("pthread join");
			continue;
		}
	}

clean_dsa:
	dsa_free(dsa);
	return 0;

}
