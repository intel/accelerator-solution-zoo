// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/vfio.h>
#include <pthread.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <accfg/libaccel_config.h>
#include <accfg/idxd.h>
#include "dsa.h"

#define DSA_COMPL_RING_SIZE 64
#define MAX_COMP_RETRY	2000000000 
unsigned int ms_timeout = 20000000;
int debug_logging;
static int umwait_support;

static inline void cpuid(unsigned int *eax, unsigned int *ebx,
		unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
		: "=a" (*eax),
		"=b" (*ebx),
		"=c" (*ecx),
		"=d" (*edx)
		: "0" (*eax), "2" (*ecx)
		: "memory");
}

struct dsa_context *dsa_init(void)
{
	struct dsa_context *dctx;
	unsigned int unused[2];
	unsigned int leaf, waitpkg;
	int rc;
	struct accfg_ctx *ctx;

	/* detect umwait support */
	leaf = 7;
	waitpkg = 0;
	cpuid(&leaf, unused, &waitpkg, unused+1);
	if (waitpkg & 0x20) {
		dbg("umwait supported\n");
		umwait_support = 1;
	}

	dctx = malloc(sizeof(struct dsa_context));
	if (!dctx)
		return NULL;
	memset(dctx, 0, sizeof(struct dsa_context));

	if (pthread_mutex_init(&dctx->tlock, NULL)) {
		dbg("init tlock failed\n");
		free(dctx);
		return NULL;
	}
	dctx->nth = MAX_USE_CPUS;
	rc = accfg_new(&ctx);
	if (rc < 0) {
		free(dctx);
		return NULL;
	}

	dctx->ctx = ctx;
	return dctx;
}

static int is_symlink(char *path)
{
	struct stat sb;
	if(path == NULL) {
		fprintf(stderr, "Invalid input for is_symlink.\n");
		return -1;
	}

	memset(&sb, 0, sizeof(struct stat));

	if (lstat(path, &sb) == -1) {
		fprintf(stderr, "lstat failed\n");
		return -1;
        }
	
	if ((sb.st_mode & S_IFMT) == S_IFLNK) {
		return 1;
	}

	return 0;

}

static int dsa_setup_wq(struct dsa_context *ctx, struct accfg_wq *wq)
{
	char path[PATH_MAX];
	int rc;

	rc = accfg_wq_get_user_dev_path(wq, path, PATH_MAX);
	if (rc) {
		fprintf(stderr, "Error getting uacce device path\n");
		return rc;
	}
	
	if(is_symlink(path) == 1) {
		fprintf(stderr, "It's a symlink file, according to CWE-59, it's un-safe to open a symlink file.\n");
		return -1;
	}
	ctx->fd = open(path, O_RDWR);
	if (ctx->fd < 0) {
		perror("open");
		return -errno;
	}

	ctx->wq_reg = mmap(NULL, 0x1000, PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ctx->fd, 0);
	if (ctx->wq_reg == MAP_FAILED) {
		perror("mmap");
		return -errno;
	}

	return 0;
}

static struct accfg_wq *dsa_get_wq(struct dsa_context *ctx,
		int dev_id, int wq_id, int shared)
{
	struct accfg_device *device;
	struct accfg_wq *wq;
	int rc;

	accfg_device_foreach(ctx->ctx, device) {
		enum accfg_device_state dstate;

		/* Make sure that the device is enabled */
		dstate = accfg_device_get_state(device);
		if (dstate != ACCFG_DEVICE_ENABLED)
			continue;

		/* Match the device to the id requested */
		if (accfg_device_get_id(device) != dev_id &&
				dev_id != -1)
			continue;

		accfg_wq_foreach(device, wq) {
			enum accfg_wq_state wstate;
			enum accfg_wq_mode mode;
			enum accfg_wq_type type;

			if (wq_id != accfg_wq_get_id(wq) && wq_id != -1)
				continue;

			/* Get a workqueue that's enabled */
			wstate = accfg_wq_get_state(wq);
			if (wstate != ACCFG_WQ_ENABLED)
				continue;

			/* The wq type should be user */
			type = accfg_wq_get_type(wq);
			if (type != ACCFG_WQT_USER)
				continue;

			/* Make sure the mode is correct */
			mode = accfg_wq_get_mode(wq);
			if ((mode == ACCFG_WQ_SHARED && !shared)
				|| (mode == ACCFG_WQ_DEDICATED && shared))
				continue;

			rc = dsa_setup_wq(ctx, wq);
			if (rc < 0)
				continue; //return NULL;

			return wq;
		}
	}

	return NULL;
}

static uint32_t bsr(uint32_t val)
{
	uint32_t msb;

	msb = (val == 0) ? 0 : 32 - __builtin_clz(val);
	return msb - 1;
}


int dsa_alloc(struct dsa_context *ctx, int shared)
{
	return dsa_alloc_raw(ctx, -1, -1, shared);
}

int dsa_alloc_raw(struct dsa_context *ctx, int dev_id, int wq_id, int shared)
{
	struct accfg_device *dev;

	/* Is wq already allocated? */
	if (ctx->wq_reg)
		return 0;

	ctx->wq = dsa_get_wq(ctx, dev_id, wq_id, shared);
	if (!ctx->wq) {
		err("No usable wq found\n");
		return -ENODEV;
	}
	dev = accfg_wq_get_device(ctx->wq);

	ctx->dedicated = !shared;
	ctx->wq_size = accfg_wq_get_size(ctx->wq);
	ctx->wq_idx = accfg_wq_get_id(ctx->wq);
	ctx->bof = accfg_wq_get_block_on_fault(ctx->wq);
	ctx->wq_max_batch_size = accfg_wq_get_max_batch_size(ctx->wq);
	ctx->wq_max_xfer_size = accfg_wq_get_max_transfer_size(ctx->wq);
	ctx->ats_disable = accfg_wq_get_ats_disable(ctx->wq);

	ctx->max_batch_size = accfg_device_get_max_batch_size(dev);
	ctx->max_xfer_size = accfg_device_get_max_transfer_size(dev);
	ctx->max_xfer_bits = bsr(ctx->max_xfer_size);

	info("alloc device %s shared %d size %d addr %p batch sz %#x xfer sz %#x\n",
			accfg_wq_get_devname(ctx->wq),
			shared, ctx->wq_size, ctx->wq_reg,
			ctx->max_batch_size, ctx->max_xfer_size);

	return 0;
}

int alloc_task(struct dsa_context *ctx)
{
	ctx->single_task = __alloc_task();
	if (!ctx->single_task)
		return -ENOMEM;

	dbg("single task allocated, desc %#lx comp %#lx\n",
			ctx->single_task->desc, ctx->single_task->comp);

        int i;
        for(i=0; i<128; i++) {
                ctx->tasks[i] = __alloc_task();
                if (!ctx->tasks[i])
                        return -ENOMEM;

                dbg("tasks %d allocated, desc %#lx comp %#lx\n",
                                i, ctx->tasks[i]->desc, ctx->tasks[i]->comp);
        }


	return DSA_STATUS_OK;
}

int alloc_tasks(struct dsa_context *ctx)
{
	int i;
	for(i=0; i<127; i++) {
		ctx->tasks[i] = __alloc_task();
		if (!ctx->single_task)
			return -ENOMEM;

		dbg("tasks %d allocated, desc %#lx comp %#lx\n",
				i, ctx->tasks[i]->desc, ctx->tasks[i]->comp);
	}

	return DSA_STATUS_OK;
}

//called before create multiple threads
int alloc_percpu_tasks(struct dsa_context *ctx)
{
	int i;

	ctx->pct = mmap(NULL,  ctx->ncpu * sizeof(struct percpu_tasks), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ctx->pct == MAP_FAILED) {
		dbg("alloc_tasks mmap failed\n");
		return -ENOMEM;
	}
	for(i = 0; i < ctx->ncpu; i++) {
		struct percpu_tasks *ipt = &(ctx->pct[i]);
		memset(ipt, 0, sizeof(struct percpu_tasks));
		ipt->dsa_ctx = ctx;
	}

	return DSA_STATUS_OK;
}

//called in each thread
int alloc_thread_stasks(struct dsa_context *ctx, int cpuid)
{
	int i;
	struct percpu_tasks *ipt = &(ctx->pct[cpuid]);
	
	ipt->single_task = aligned_alloc(64, sizeof(struct task) * MAX_WQ_SZ);
	if(ipt->single_task == NULL) {
		dbg("alloc memory failed for stasks array\n");
		return -ENOMEM;
	}
	
	//init for each task
	for(i = 0; i < MAX_WQ_SZ; i++) {
		struct task *tsk = &(ipt->single_task[i]);
		memset(tsk, 0, sizeof(struct task));
		tsk->desc = malloc(sizeof(struct dsa_hw_desc));
		if (tsk->desc == NULL) {
			goto fail_out;
		}
		memset(tsk->desc, 0, sizeof(struct dsa_hw_desc));

		/* completion record need to be 32bits aligned */
		tsk->comp = aligned_alloc(32, sizeof(struct dsa_completion_record));
		if (tsk->comp == NULL) {
			free(tsk->desc);
			goto fail_out;
		}
		memset(tsk->comp, 0, sizeof(struct dsa_completion_record));
	}
	
	return DSA_STATUS_OK;

fail_out:
	free(ipt->single_task);
	return -ENOMEM;
}


struct task *__alloc_task(void)
{
	struct task *tsk;

	tsk = malloc(sizeof(struct task));
	if (!tsk)
		return NULL;
	memset(tsk, 0, sizeof(struct task));

	tsk->desc = malloc(sizeof(struct dsa_hw_desc));
	if (!tsk->desc) {
		free_task(tsk);
		return NULL;
	}
	memset(tsk->desc, 0, sizeof(struct dsa_hw_desc));

	/* completion record need to be 32bits aligned */
	tsk->comp = aligned_alloc(32, sizeof(struct dsa_completion_record));
	if (!tsk->comp) {
		free_task(tsk);
		return NULL;
	}
	memset(tsk->comp, 0, sizeof(struct dsa_completion_record));

	return tsk;
}

/* this function is re-used by batch task */
int init_task(struct task *tsk, int tflags, int opcode,
		unsigned long xfer_size)
{

	tsk->pattern = 0x0123456789abcdef;
	tsk->opcode = opcode;
	tsk->test_flags = tflags;
	tsk->xfer_size = xfer_size;

	/* allocate memory: src1*/
	switch (opcode) {
	case DSA_OPCODE_MEMMOVE: /* intentionally empty */
	case DSA_OPCODE_COMPARE: /* intentionally empty */
	case DSA_OPCODE_COMPVAL: /* intentionally empty */
	case DSA_OPCODE_DUALCAST:
		tsk->src1 = malloc(xfer_size);
		if (!tsk->src1)
			return -ENOMEM;
		memset_pattern(tsk->src1, tsk->pattern, xfer_size);
	}

	/* allocate memory: src2*/
	switch (opcode) {
	case DSA_OPCODE_COMPARE:
		tsk->src2 = malloc(xfer_size);
		if (!tsk->src2)
			return -ENOMEM;
		memset_pattern(tsk->src2, tsk->pattern, xfer_size);
	}

	/* allocate memory: dst1*/
	switch (opcode) {
	case DSA_OPCODE_MEMMOVE: /* intentionally empty */
	case DSA_OPCODE_MEMFILL: /* intentionally empty */
	case DSA_OPCODE_DUALCAST:
		/* DUALCAST: dst1/dst2 lower 12 bits must be same */
		tsk->dst1 = aligned_alloc(1<<12, xfer_size);
		if (!tsk->dst1)
			return -ENOMEM;
		if (tflags & TEST_FLAGS_PREF)
			memset(tsk->dst1, 0, xfer_size);
	}

	/* allocate memory: dst2*/
	switch (opcode) {
	case DSA_OPCODE_DUALCAST:
		/* DUALCAST: dst1/dst2 lower 12 bits must be same */
		tsk->dst2 = aligned_alloc(1<<12, xfer_size);
		if (!tsk->dst2)
			return -ENOMEM;
		if (tflags & TEST_FLAGS_PREF)
			memset(tsk->dst2, 0, xfer_size);
	}

	dbg("Mem allocated: s1 %#lx s2 %#lx d1 %#lx d2 %#lx\n",
			tsk->src1, tsk->src2, tsk->dst1, tsk->dst2);

	return DSA_STATUS_OK;
}

int alloc_batch_task(struct dsa_context *ctx, unsigned int task_num)
{
	struct batch_task *btsk;

	if (!ctx->is_batch) {
		err("%s is valid only if 'is_batch' is enabled", __func__);
		return -EINVAL;
	}

	ctx->batch_task = malloc(sizeof(struct batch_task));
	if (!ctx->batch_task)
		return -ENOMEM;
	memset(ctx->batch_task, 0, sizeof(struct batch_task));

	btsk = ctx->batch_task;

	btsk->core_task = __alloc_task();
	if (!btsk->core_task)
		return -ENOMEM;

	btsk->sub_tasks = malloc(task_num * sizeof(struct task));
	if (!btsk->sub_tasks)
		return -ENOMEM;
	memset(btsk->sub_tasks, 0, task_num * sizeof(struct task));

	btsk->sub_descs = aligned_alloc(64,
			task_num * sizeof(struct dsa_hw_desc));
	if (!btsk->sub_descs)
		return -ENOMEM;
	memset(btsk->sub_descs, 0, task_num * sizeof(struct dsa_hw_desc));

	btsk->sub_comps = aligned_alloc(32,
			task_num * sizeof(struct dsa_completion_record));
	if (!btsk->sub_comps)
		return -ENOMEM;
	memset(btsk->sub_comps, 0,
			task_num * sizeof(struct dsa_completion_record));

	dbg("batch task allocated %#lx, ctask %#lx, sub_tasks %#lx\n",
			btsk, btsk->core_task, btsk->sub_tasks);
	dbg("sub_descs %#lx, sub_comps %#lx\n",
			btsk->sub_descs, btsk->sub_comps);

	return DSA_STATUS_OK;
}

int init_batch_task(struct batch_task *btsk, int task_num, int tflags,
		int opcode, unsigned long xfer_size, unsigned long dflags)
{
	int i, rc;

	btsk->task_num = task_num;
	btsk->test_flags = tflags;

	for (i = 0; i < task_num; i++) {
		btsk->sub_tasks[i].desc = &(btsk->sub_descs[i]);
		btsk->sub_tasks[i].comp = &(btsk->sub_comps[i]);
		btsk->sub_tasks[i].dflags = dflags;
		rc = init_task(&(btsk->sub_tasks[i]), tflags, opcode,
				xfer_size);
		if (rc != DSA_STATUS_OK) {
			err("batch: init sub-task failed\n");
			return rc;
		}
	}

	return DSA_STATUS_OK;
}

int dsa_enqcmd(struct dsa_context *ctx, struct dsa_hw_desc *hw)
{
	int retry_count = 0;
	int ret = 0;

	while (retry_count < 3) {
		if (!enqcmd(ctx->wq_reg, hw))
			break;

	//	info("retry\n");
		retry_count++;
	}

	return ret;
}

static inline unsigned long rdtsc(void)
{
	uint32_t a, d;

	asm volatile("rdtsc" : "=a"(a), "=d"(d));
	return ((uint64_t)d << 32) | (uint64_t)a;
}

static inline void umonitor(volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

static inline int umwait(unsigned long timeout, unsigned int state)
{
	uint8_t r;
	uint32_t timeout_low = (uint32_t)timeout;
	uint32_t timeout_high = (uint32_t)(timeout >> 32);

	timeout_low = (uint32_t)timeout;
	timeout_high = (uint32_t)(timeout >> 32);

	asm volatile(".byte 0xf2, 0x48, 0x0f, 0xae, 0xf1\t\n"
		"setc %0\t\n"
		: "=r"(r)
		: "c"(state), "a"(timeout_low), "d"(timeout_high));
	return r;
}

static int dsa_wait_on_desc_timeout(struct dsa_completion_record *comp,
		unsigned int msec_timeout)
{
	unsigned int j = 0;

	if (!umwait_support) {
		while (j < msec_timeout && comp->status == 0) {
			usleep(1000);
			j++;
		}
	} else {
		unsigned long timeout = (ms_timeout * 1000000) * 3;
		int r = 1;
		unsigned long t = 0;

		timeout += rdtsc();
		while (comp->status == 0) {
			if (!r) {
				t = rdtsc();
				if (t >= timeout) {
					err("umwait timeout %#lx\n", t);
					break;
				}
			}

			umonitor((uint8_t *)comp);
			if (comp->status != 0)
				break;
			r = umwait(timeout, 0);
		}
		if (t >= timeout)
			j = msec_timeout;
	}

	dump_compl_rec(comp);

	return (j == msec_timeout) ? -EAGAIN : 0;
}

/* the pattern is 8 bytes long while the dst can with any length */
void memset_pattern(void *dst, uint64_t pattern, size_t len)
{
	size_t len_8_aligned, len_remainding, mask = 0x7;
	uint64_t *aligned_end, *tmp_64;

	/* 8 bytes aligned part */
	len_8_aligned = len & ~mask;
	aligned_end = (uint64_t *)((uint8_t *)dst + len_8_aligned);
	tmp_64 = (uint64_t *)dst;
	while (tmp_64 < aligned_end) {
		*tmp_64 = pattern;
		tmp_64++;
	}

	/* non-aligned part */
	len_remainding = len & mask;
	memcpy(aligned_end, &pattern, len_remainding);
}

/* return 0 if src is a repeatation of pattern, -1 otherwise */
/* the pattern is 8 bytes long and the src could be with any length */
int memcmp_pattern(const void *src, const uint64_t pattern, size_t len)
{
	size_t len_8_aligned, len_remainding, mask = 0x7;
	uint64_t *aligned_end, *tmp_64;

	/* 8 bytes aligned part */
	len_8_aligned = len & ~mask;
	aligned_end = (void *)((uint8_t *)src + len_8_aligned);
	tmp_64 = (uint64_t *)src;
	while (tmp_64 < aligned_end) {
		if (*tmp_64 != pattern)
			return -1;
		tmp_64++;
	}

	/* non-aligned part */
	len_remainding = len & mask;
	if (memcmp(aligned_end, &pattern, len_remainding))
		return -1;

	return 0;
}

void dsa_free(struct dsa_context *ctx)
{
	if (munmap(ctx->wq_reg, 0x1000))
		err("munmap failed %d\n", errno);

	close(ctx->fd);

	accfg_unref(ctx->ctx);
	dsa_free_task(ctx);
	free(ctx);
}

void dsa_free_task(struct dsa_context *ctx)
{
	if (!ctx->is_batch)
		free_task(ctx->single_task);
	else
		free_batch_task(ctx->batch_task);
}

void free_task(struct task *tsk)
{
	__clean_task(tsk);
	free(tsk);
}

/* The components of task is free but not the struct task itself */
/* This function is re-used by free_batch_task() */
void __clean_task(struct task *tsk)
{
	if (!tsk)
		return;

	free(tsk->desc);
	free(tsk->comp);
}

void free_batch_task(struct batch_task *btsk)
{
	int i;

	if (!btsk)
		return;

	free_task(btsk->core_task);

	for (i = 0; i < btsk->task_num; i++) {
		/* pointing to part of the 'btsk->sub_descs/comps', need to */
		/* free the buffer as a whole out of the loop. Set to NULL */
		/* to avoid being free in __clean_task()*/
		btsk->sub_tasks[i].desc = NULL;
		btsk->sub_tasks[i].comp = NULL;
		/* sub_tasks is an array "btsk->sub_tasks", we don't free */
		/* btsk->sub_tasks[i] itself here */
		__clean_task(&(btsk->sub_tasks[i]));
	}

	free(btsk->sub_tasks);
	free(btsk->sub_descs);
	free(btsk->sub_comps);
	free(btsk);
}

int dsa_wait_batch(struct dsa_context *ctx)
{
	int rc;

	struct batch_task *btsk = ctx->batch_task;
	struct task *ctsk = btsk->core_task;

	//info("wait batch\n");

	rc = dsa_wait_on_desc_timeout(ctsk->comp, ms_timeout);
	if (rc < 0) {
		err("batch desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	dump_sub_compl_rec(btsk);
	return DSA_STATUS_OK;
}

int dsa_wait_memcpy(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("memcpy desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_memcpy(ctx, ctx->single_task);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_wait_memcpy1(struct task *tsk)
{
        struct dsa_completion_record *comp = tsk->comp;
        int rc;

        rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
        if (rc < 0) {
                err("memcpy desc timeout\n");
                return -DSA_STATUS_TIMEOUT;
        }

        /* re-submit if PAGE_FAULT reported by HW && BOF is off */
	/* we don't need to handle page-fault, we set memory content before using
        if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
                        !(desc->flags & IDXD_OP_FLAG_BOF)) {
                dsa_reprep_memcpy(ctx);
                goto again;
        }
	*/
        return DSA_STATUS_OK;
}


int dsa_memcpy(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_memcpy(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_memcpy(ctx);

	return ret;
}


static inline void
// unsigned char **src_arr : 128个同样大小的数组
// unsigned char **dst_arr : 目的大小的数组
// int blen: 每个数组的大小
copy_use_cpu(unsigned char **src_arr, unsigned char **dst_arr, int nb_bufs,  uint32_t buf_len)
{
	uint32_t j;
	for (j = 0; j < nb_bufs; j++) {
		memcpy(dst_arr[j], src_arr[j], buf_len);
	}
}

// set_async_cpy_addr(tasks, src_arr,dst_arr, nb_bufs, len);
void set_task_buffer(struct task tasks[],
						unsigned char **src_arr, 
 						unsigned char **dst_arr, int nb_bufs, int buf_len) 
	{
	 for (int j = 0; j < nb_bufs; ++j) {
	 	tasks[j].xfer_size = buf_len;
		tasks[j].src1 = src_arr[j];
		tasks[j].dst1 = dst_arr[j];
		dsa_prep_memcpy(&tasks[j]);
	 }
	 __builtin_ia32_sfence();
}

void dsa_async_subinit( struct dsa_context *ctx,
						struct task tasks[],
						struct dsa_hw_desc *sub_descs,
						struct dsa_completion_record *sub_comps, int nb_bufs) 
 {
	sub_descs = aligned_alloc(64, nb_bufs * sizeof(struct dsa_hw_desc));
	sub_comps = aligned_alloc(32, nb_bufs * sizeof(struct dsa_completion_record));
	memset(tasks, 0, nb_bufs * sizeof(struct task));
	memset(sub_descs, 0, nb_bufs * sizeof(struct dsa_hw_desc));
	memset(sub_comps, 0, nb_bufs * sizeof(struct dsa_completion_record));
	for (int j = 0; j < nb_bufs; ++j) {
		tasks[j].desc = &sub_descs[j];
		tasks[j].comp = &sub_comps[j];
		tasks[j].opcode = DSA_OPCODE_MEMMOVE;
		tasks[j].dflags = TEST_TAKS_DFLGS;
		if ((tasks[j].test_flags & TEST_FLAGS_BOF) && ctx->bof)
			tasks[j].dflags |= IDXD_OP_FLAG_BOF;
		tasks[j].desc->flags = TEST_TAKS_DFLGS;
	}
}
int
dsa_memcpy_vector_with_tasks(
 struct dsa_context *ctx, struct task tasks[],  int nb_bufs) {
	uint32_t j;
	int lcnt = 0;
	for (j = 0; j < nb_bufs; ++j) {
		dsa_desc_submit(ctx, (&tasks[j])->desc);
	}
	for (j = 0; j < nb_bufs; ++j) {
		while (!tasks[j].comp->status && ++lcnt < MAX_COMP_RETRY);
		if (lcnt >= MAX_COMP_RETRY){
			printf("%d timed out \n ", j);
			return DSA_STATUS_FAIL;
		}
		lcnt = 0;
	}
	return DSA_STATUS_OK;
}

// unsigned char **src_arr : nb_bufs个同样大小的数组
// unsigned char **dst_arr : 目的大小的数组
// int blen: 每个数组的大小
int dsa_memcpy_vector(struct dsa_context *ctx, unsigned char **src_arr, unsigned char **dst_arr,int nb_bufs, int buf_len) 
{
	uint32_t j;
	int lcnt;
	struct task tasks[nb_bufs];
	struct dsa_hw_desc *sub_descs; 
	struct dsa_completion_record *sub_comps;
	sub_descs = aligned_alloc(64, nb_bufs * sizeof(struct dsa_hw_desc));
	sub_comps = aligned_alloc(32, nb_bufs * sizeof(struct dsa_completion_record));
	memset(tasks, 0, nb_bufs * sizeof(struct task));
	memset(sub_descs, 0, nb_bufs * sizeof(struct dsa_hw_desc));
	memset(sub_comps, 0, nb_bufs * sizeof(struct dsa_completion_record));
	// init descs, comps array
	for (j = 0; j < nb_bufs; ++j) {
		tasks[j].desc = &sub_descs[j];
		tasks[j].comp = &sub_comps[j];
		tasks[j].opcode = DSA_OPCODE_MEMMOVE;
		tasks[j].xfer_size = buf_len;
		tasks[j].src1 = src_arr[j];
		tasks[j].dst1 = dst_arr[j];
		tasks[j].dflags = 268;
		dsa_prep_memcpy(&tasks[j]);
		tasks[j].desc->flags = 268;
	}
	__builtin_ia32_sfence();
	lcnt = 0;
	for (j = 0; j < nb_bufs; ++j) {
		dsa_desc_submit(ctx, (&tasks[j])->desc);
	}
	for (j = 0; j < nb_bufs; ++j) {
		while (!tasks[j].comp->status && ++lcnt < MAX_COMP_RETRY);
		if (lcnt >= MAX_COMP_RETRY){
			free(sub_descs);
			free(sub_comps);
			return DSA_STATUS_FAIL;
		}
		lcnt = 0;
	}
	free(sub_descs);
	free(sub_comps);
	return DSA_STATUS_OK;
}

int dsa_memcpy_vector1(struct percpu_tasks *ppt, unsigned char **src_arr, unsigned char **dst_arr,int nb_bufs, int buf_len)
{
	int i;
        struct task *tsk = NULL;
        //size_t atask;
	int fcnt = 0;
        struct dsa_context *ctx = NULL;

        if(ppt == NULL){
                printf("invalid input dsa context.\n");
                return -1;
        }

        if(src_arr == NULL || dst_arr == NULL || buf_len == 0 || nb_bufs > MAX_WQ_SZ) {
                printf("invalid input parameter.\n");
                return -1;
        }
        ctx = ppt->dsa_ctx;
        if(ctx == NULL) {
                printf("invalid dsa context\n");
                return -1;
        }
	
	if(ppt->single_task == NULL) {
		printf("single task arrary don't alloc memory\n");
		return -1;
	}
	for(i = 0; i < nb_bufs; i++) {
		tsk = &(ppt->single_task[i]);
		tsk->opcode = DSA_OPCODE_MEMMOVE;
        	tsk->xfer_size = buf_len;
        	tsk->src1 = src_arr[i];
        	tsk->dst1 = dst_arr[i];
		tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
		dsa_prep_memcpy(tsk);
	
		__builtin_ia32_sfence();
		dsa_desc_submit(ctx, tsk->desc);
	}

	for(i = 0; i < nb_bufs; i++) {
		tsk = &(ppt->single_task[i]);
		while (tsk->comp->status != DSA_COMP_SUCCESS && ++fcnt < MAX_COMP_RETRY);
		if (fcnt >= MAX_COMP_RETRY){
                        return DSA_STATUS_FAIL;
                }
                fcnt = 0;
	}
	return DSA_STATUS_OK;
}


int memcpy_decision(bool dma, uint32_t nb_bufs, 
					struct dsa_context *ctx, struct task tasks[], 
					unsigned char **src_arr, unsigned char **dst_arr, 
					uint64_t len)
{
	if (!dma) {
		// use cpu
		copy_use_cpu(src_arr, dst_arr, nb_bufs, len);
		return 0;

	} else {
		// use dsa
		return dsa_memcpy_vector_with_tasks(ctx, tasks, nb_bufs);
	}
}

int dsa_memcpy_vector_async_submit(struct dsa_context *ctx, void *src, void *dst, uint64_t len)
{
	struct task *tsk = NULL;

	if(ctx == NULL){
		printf("invalid input dsa context.\n");
                return -1;
	}

	if(src == NULL || dst == NULL || len == 0) {
		printf("invalid input memory address.\n");
		return -1;
	}

        if(ctx->task_nb > 127) {
                printf("task nb overflow");
                return -1;
        }

        tsk = ctx->tasks[ctx->task_nb];

	if(tsk == NULL) {
		printf("alloc task for ctx first! task nb :%d\n", ctx->task_nb);
		return -1;
	}
	tsk->opcode = DSA_OPCODE_MEMMOVE;
	tsk->xfer_size = len;
	tsk->src1 = src;
	tsk->dst1 = dst;

	tsk->dflags = 268;
	dsa_prep_memcpy(tsk);

	__builtin_ia32_sfence();

	dsa_desc_submit(ctx, tsk->desc);

	ctx->task_nb++;
	return 0;

}
//src and dst address alloc from memalign with 4k, perf will be better
int dsa_memcpy_single(struct dsa_context *ctx, void *src, void *dst, uint64_t len)
{
	int rc = -1;
	struct task *tsk = NULL;
	
	if(ctx == NULL){
		printf("invalid input dsa context.\n");
                return -1;
	}

	if(src == NULL || dst == NULL || len == 0) {
		printf("invalid input memory address.\n");
		return -1;
	}

	tsk = ctx->single_task;
	if(tsk == NULL) {
		printf("alloc single task for ctx first!\n");
		return -1;
	}
	tsk->opcode = DSA_OPCODE_MEMMOVE;
	tsk->xfer_size = len;
	tsk->src1 = src;
	tsk->dst1 = dst;
	
	rc = dsa_memcpy(ctx);
	if (rc != DSA_STATUS_OK) {
		err("memcpy failed stat %d\n", rc);
		return -1;
	}

	return DSA_STATUS_OK;
}


int dsa_memcpy_single1(struct percpu_tasks *ppt, void *src, void *dst, uint64_t len)
{
        int rc = -1;
        struct task *tsk = NULL;
	size_t atask;
	struct dsa_context *ctx = NULL;
	uint64_t st,end;
	
	st = rdtsc();
        if(ppt == NULL){
                printf("invalid input dsa context.\n");
                return -1;
        }

        if(src == NULL || dst == NULL || len == 0) {
                printf("invalid input memory address.\n");
                return -1;
        }
	ctx = ppt->dsa_ctx;
	if(ctx == NULL) {
		printf("invalid dsa context\n");
		return -1;
	}
	if(ppt->cpuid < 0 || ppt->cpuid > MAX_USE_CPUS) {
		printf("invalid cpuid\n");
		return -1;
	}

	//find first available single task slot to use. for single mode, we always use first task.
        atask=1; //atask = find_first_zero_bit(ppt->task_bm, MAX_WQ_SZ);
	tsk = &(ppt->single_task[atask]);
        if(tsk == NULL) {
                printf("Empty task at %zu!\n", atask);
                return -1;
        }
        tsk->opcode = DSA_OPCODE_MEMMOVE;
        tsk->xfer_size = len;
        tsk->src1 = src;
        tsk->dst1 = dst;
	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	//if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
	//	tsk->dflags |= IDXD_OP_FLAG_BOF;
	dsa_prep_memcpy(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	end=rdtsc();
	//printf("submit cost=%ld cycles, cpuid:%d, running-core:%d.\n", end - st, ppt->cpuid, sched_getcpu());
	rc = dsa_wait_memcpy1(tsk);

        return rc;
}

int dsa_memcpy_async_submit(struct dsa_context *ctx, void *src, void *dst, uint64_t len)
{
	struct task *tsk = NULL;
	
	if(ctx == NULL){
		printf("invalid input dsa context.\n");
                return -1;
	}

	if(src == NULL || dst == NULL || len == 0) {
		printf("invalid input memory address.\n");
		return -1;
	}

	tsk = ctx->single_task;
	if(tsk == NULL) {
		printf("alloc single task for ctx first!\n");
		return -1;
	}
	tsk->opcode = DSA_OPCODE_MEMMOVE;
	tsk->xfer_size = len;
	tsk->src1 = src;
	tsk->dst1 = dst;
	
        tsk->dflags = 268;
        dsa_prep_memcpy(tsk);

        __builtin_ia32_sfence();

        dsa_desc_submit(ctx, tsk->desc);
	ctx->start = rdtsc();

	return DSA_STATUS_OK;
}

int dsa_memcpy_async_submit1(struct percpu_tasks *ppt, void *src, void *dst, uint64_t len)
{
        struct task *tsk = NULL;
	struct dsa_context *ctx = NULL;
	size_t at = 0;

        if(ppt == NULL){
                printf("invalid input dsa per thread context.\n");
                return -1;
        }

        if(src == NULL || dst == NULL || len == 0) {
                printf("invalid input memory address.\n");
                return -1;
        }

	ctx = ppt->dsa_ctx;
	if(ctx == NULL) {
                printf("invalid dsa context\n");
                return -1;
        }
	at = find_first_zero_bit(ppt->task_bm, MAX_WQ_SZ);
	tsk = &(ppt->single_task[at]);
	if(tsk == NULL) {
                printf("Empty task at %zu!\n", at);
                return -1;
        }
        
	tsk->opcode = DSA_OPCODE_MEMMOVE;
        tsk->xfer_size = len;
        tsk->src1 = src;
        tsk->dst1 = dst;
	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	dsa_prep_memcpy(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	set_bit(at, ppt->task_bm);


        return DSA_STATUS_OK;
}

int dsa_memcpy_async_submit_vector(struct percpu_tasks *ppt, unsigned char **src_arr, unsigned char **dst_arr,int nb_bufs, int buf_len)
{
	int i;
        struct task *tsk = NULL;
        size_t at;
        struct dsa_context *ctx = NULL;

	if(ppt == NULL){
                printf("invalid input dsa context.\n");
                return -1;
        }

        if(src_arr == NULL || dst_arr == NULL || buf_len == 0 || nb_bufs > MAX_WQ_SZ) {
                printf("invalid input parameter.\n");
                return -1;
        }
        ctx = ppt->dsa_ctx;
        if(ctx == NULL) {
                printf("invalid dsa context\n");
                return -1;
        }
	
	for(i = 0; i < nb_bufs; i++) {
		//tsk = &(ppt->single_task[i]);
		at = find_first_zero_bit(ppt->task_bm, MAX_WQ_SZ);
        	tsk = &(ppt->single_task[at]);

		tsk->opcode = DSA_OPCODE_MEMMOVE;
        	tsk->xfer_size = buf_len;
        	tsk->src1 = src_arr[i];
        	tsk->dst1 = dst_arr[i];
		tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
		dsa_prep_memcpy(tsk);
	
		__builtin_ia32_sfence();
		dsa_desc_submit(ctx, tsk->desc);
		set_bit(at, ppt->task_bm);
	}
	return DSA_STATUS_OK;
}

/*
 *check nr completed tasks, if need wait, user can call sleep outside this function.
 *if no error, return completed number of tasks.
 */

int dsa_memcpy_check_comp(struct percpu_tasks *ppt, int nr)
{
	size_t it;
	struct dsa_context *ctx = NULL;
	int cnt = 0;
	struct task *tsk = NULL;

	if(ppt == NULL || nr < 1 ){
                printf("invalid input parameter.\n");
                return -1;
        }

	ctx = ppt->dsa_ctx;
        if(ctx == NULL) {
                printf("invalid dsa context\n");
                return -1;
        }
	
	for_each_set_bit(it, ppt->task_bm, MAX_WQ_SZ) {
		tsk = &(ppt->single_task[it]);
		if(tsk->comp->status == DSA_COMP_SUCCESS) {
			cnt ++;
			clear_bit(it, ppt->task_bm);
		}

		if(cnt >= nr) {
			break;
		}
	}

	return cnt;
}

int dsa_wait_memcpy_async(struct dsa_context *ctx)
{
	static unsigned cnt;
	struct task *tsk = ctx->single_task;
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int ret = DSA_STATUS_OK;

	if(tsk->comp->status) {
		if(cnt++ % 10000 == 0) {
			printf("dsa memcpy finished, costed %lu cycles\n",rdtsc() - ctx->start);
			printf("dsa comp status: %d\n",tsk->comp->status);
		}
		if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
				!(desc->flags & IDXD_OP_FLAG_BOF)) {
			ret = dsa_wait_memcpy(ctx);
			return ret;
			
		}
		ctx->start = 0;
		return DSA_STATUS_OK;
	}
	if(rdtsc() - ctx->start > (ms_timeout * 1000000) * 3)
		return DSA_STATUS_FAIL;
	
	return DSA_STATUS_RETRY;	
}

int dsa_wait_memcpy_vector_async(struct dsa_context *ctx)
{
        uint32_t j;
        int lcnt = 0;
        for (j = 0; j < ctx->task_nb; ++j) {
again:
                while (!ctx->tasks[j]->comp->status && ++lcnt < MAX_COMP_RETRY);
                if (lcnt >= MAX_COMP_RETRY){
                        ctx->task_nb = 0;
                        return DSA_STATUS_FAIL;
                }
                lcnt = 0;
                if (stat_val(ctx->tasks[j]->comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
                                !(ctx->tasks[j]->desc->flags & IDXD_OP_FLAG_BOF)) {
                        dsa_reprep_memcpy(ctx, ctx->tasks[j]);
                        goto again;
                }
        }
        ctx->task_nb = 0;
        return DSA_STATUS_OK;
}

//for batch memcpy copy
int dsa_memcpy_batch(struct dsa_context *ctx, unsigned char **src_arr, unsigned char **dst_arr, size_t bnum, uint64_t len)
{
	int rc = -1, i = 0;
	uint64_t dflags = 0;
	struct batch_task *btsk = NULL; //ctx->batch_task;
	
	if(ctx == NULL){
                printf("invalid input dsa context.\n");
                return -1;
        }

        if(src_arr == NULL || dst_arr == NULL || bnum == 0 ||len == 0) {
                printf("invalid input memory address.\n");
                return -1;
        }
	
        btsk = ctx->batch_task;
        if(btsk == NULL) {
                printf("alloc batch task for ctx first!\n");
                return -1;
        }
	
	btsk->task_num = bnum;
	dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	//btsk->test_flags = dflags;

	for(i = 0; i < bnum; i++) {
		struct task *sti = &(btsk->sub_tasks[i]);
		sti->desc = &(btsk->sub_descs[i]);
		sti->comp = &(btsk->sub_comps[i]);
		sti->dflags = dflags;
		
		sti->opcode = DSA_OPCODE_MEMMOVE;
		sti->xfer_size = len;
		sti->src1 = src_arr[i];
		sti->dst1 = dst_arr[i];
		
		dsa_prep_desc_common(sti->desc, sti->opcode, (uint64_t)(sti->dst1), (uint64_t)(sti->src1), sti->xfer_size, sti->dflags);
		sti->desc->completion_addr = (uint64_t)(sti->comp);
		sti->comp->status = 0;
	}


	dsa_prep_batch(ctx->batch_task, dflags);
	unsigned long start, end;
	start = rdtsc();
	dsa_desc_submit(ctx, btsk->core_task->desc);
	
	rc = dsa_wait_on_desc_timeout(btsk->core_task->comp, ms_timeout);
	end = rdtsc();
	printf("cpu memcpy cost cpu real cycles: %lu\n",(end - start) / bnum);
	
	if(rc < 0) {
		printf("batch desc timeout!\n");
		return DSA_STATUS_TIMEOUT;
	}
	return DSA_STATUS_OK;
}

int dsa_wait_memfill(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("memfill desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_memfill(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_memfill(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_memfill(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_memfill(ctx);

	return ret;
}

int dsa_wait_compare(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("compare desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_compare(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compare(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_compare(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_compare(ctx);

	return ret;
}

int dsa_wait_compval(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);

	if (rc < 0) {
		err("compval desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_compval(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_compval(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_compval(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_compval(ctx);

	return ret;
}

int dsa_wait_dualcast(struct dsa_context *ctx)
{
	struct dsa_hw_desc *desc = ctx->single_task->desc;
	struct dsa_completion_record *comp = ctx->single_task->comp;
	int rc;

again:
	rc = dsa_wait_on_desc_timeout(comp, ms_timeout);
	if (rc < 0) {
		err("dualcast desc timeout\n");
		return DSA_STATUS_TIMEOUT;
	}

	/* re-submit if PAGE_FAULT reported by HW && BOF is off */
	if (stat_val(comp->status) == DSA_COMP_PAGE_FAULT_NOBOF &&
			!(desc->flags & IDXD_OP_FLAG_BOF)) {
		dsa_reprep_dualcast(ctx);
		goto again;
	}

	return DSA_STATUS_OK;
}

int dsa_dualcast(struct dsa_context *ctx)
{
	struct task *tsk = ctx->single_task;
	int ret = DSA_STATUS_OK;

	tsk->dflags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if ((tsk->test_flags & TEST_FLAGS_BOF) && ctx->bof)
		tsk->dflags |= IDXD_OP_FLAG_BOF;

	dsa_prep_dualcast(tsk);
	dsa_desc_submit(ctx, tsk->desc);
	ret = dsa_wait_dualcast(ctx);

	return ret;
}

/* mismatch_expected: expect mismatched buffer with success status 0x1 */
int task_result_verify(struct task *tsk, int mismatch_expected)
{
	int rc;

	//info("verifying task result for %#lx\n", tsk);

	if (tsk->comp->status != DSA_COMP_SUCCESS)
		return tsk->comp->status;

	switch (tsk->opcode) {
	case DSA_OPCODE_MEMMOVE:
		rc = task_result_verify_memcpy(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_MEMFILL:
		rc = task_result_verify_memfill(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_COMPARE:
		rc = task_result_verify_compare(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_COMPVAL:
		rc = task_result_verify_compval(tsk, mismatch_expected);
		return rc;
	case DSA_OPCODE_DUALCAST:
		rc = task_result_verify_dualcast(tsk, mismatch_expected);
		return rc;
	}

	//info("test with op %d passed\n", tsk->opcode);

	return DSA_STATUS_OK;
}

int task_result_verify_memcpy(struct task *tsk, int mismatch_expected)
{
	int rc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = memcmp(tsk->src1, tsk->dst1, tsk->xfer_size);
	if (rc) {
		err("memcpy mismatch, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int task_result_verify_memfill(struct task *tsk, int mismatch_expected)
{
	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	if (memcmp_pattern(tsk->dst1, tsk->pattern, tsk->xfer_size)) {
		err("memfill test failed\n");
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int task_result_verify_compare(struct task *tsk, int mismatch_expected)
{
	if (!mismatch_expected) {
		if (tsk->comp->result) {
			err("compval failed at %#x\n",
					tsk->comp->bytes_completed);
			return -ENXIO;
		}
		return DSA_STATUS_OK;
	}

	/* mismatch_expected */
	if (tsk->comp->result) {
		info("expected mismatch at index %#x\n",
				tsk->comp->bytes_completed);
		return DSA_STATUS_OK;
	}

	err("DSA wrongly says matching buffers\n");
	return -ENXIO;
}

int task_result_verify_compval(struct task *tsk, int mismatch_expected)
{
	if (!mismatch_expected) {
		if (tsk->comp->result) {
			err("compval failed at %#x\n",
					tsk->comp->bytes_completed);
			return -ENXIO;
		}
		return DSA_STATUS_OK;
	}

	/* mismatch_expected */
	if (tsk->comp->result) {
		info("expected mismatch at index %#x\n",
				tsk->comp->bytes_completed);
		return DSA_STATUS_OK;
	}

	err("DSA wrongly says matching buffers\n");
	return -ENXIO;
}

int task_result_verify_dualcast(struct task *tsk, int mismatch_expected)
{
	int rc;

	if (mismatch_expected)
		warn("invalid arg mismatch_expected for %d\n", tsk->opcode);

	rc = memcmp(tsk->src1, tsk->dst1, tsk->xfer_size);
	if (rc) {
		err("ducalcast mismatch dst1, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	rc = memcmp(tsk->src1, tsk->dst2, tsk->xfer_size);
	if (rc) {
		err("ducalcast mismatch dst2, memcmp rc %d\n", rc);
		return -ENXIO;
	}

	return DSA_STATUS_OK;
}

int batch_result_verify(struct batch_task *btsk, int bof)
{
	uint8_t core_stat, sub_stat;
	int i, rc;
	struct task *tsk;

	core_stat = stat_val(btsk->core_task->comp->status);
	if (core_stat == DSA_COMP_SUCCESS)
		info("core task success, chekcing sub-tasks\n");
	else if (!bof && core_stat == DSA_COMP_BATCH_FAIL)
		info("partial complete with NBOF, checking sub-tasks\n");
	else {
		err("batch core task failed with status %d\n", core_stat);
		return DSA_STATUS_FAIL;
	}

	for (i = 0; i < btsk->task_num; i++) {
		tsk = &(btsk->sub_tasks[i]);
		sub_stat = stat_val(tsk->comp->status);

		if (!bof && sub_stat == DSA_COMP_PAGE_FAULT_NOBOF)
			dbg("PF in sub-task[%d], consider as passed\n", i);
		else if (sub_stat == DSA_COMP_SUCCESS) {
			rc = task_result_verify(tsk, 0);
			if (rc != DSA_STATUS_OK) {
				err("Sub-task[%d] failed with rc=%d", i, rc);
				return rc;
			}
		} else {
			err("Sub-task[%d] failed with stat=%d", i, sub_stat);
			return DSA_STATUS_FAIL;
		}
	}

	return DSA_STATUS_OK;
}
