#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "sfifo.h"

/*a simple fifo implement, only support ane-in-one-out*/

#if 0
#define MAX_ENTRY 16

#ifndef smp_wmb
#define smp_wmb __sync_synchronize
#endif

struct entry {
	void *pdata; //pdata == NULL means this entry is empty
	int size;    //size of pdata
};

struct sfifo {
	struct entry entry_arr[MAX_ENTRY];
	int tail;
	int head;
	int freen;
};
#endif

struct sfifo *sfifo_create()
{
	int i;
	struct sfifo *ps;
	ps = calloc(sizeof(struct sfifo), 1);
	if(ps == NULL) {
		printf("calloc failed!\n");
		return NULL;
	}
	ps->freen = MAX_ENTRY;
	return ps;
}

void sfifo_free(struct sfifo *ps)
{
	int i;
	if(ps == NULL) {
		printf("empty sfifo!\n");
		return;
	}
	
	for(i = 0; i < MAX_ENTRY; i++) {
		if(ps->entry_arr[i].pdata == NULL) continue;
		free(ps->entry_arr[i].pdata);
	}
	
	free(ps);
}

int sfifo_in(struct sfifo *ps, void *buff, int sz)
{
	
	if(ps == NULL || buff == NULL || sz < 1) {
		printf("invalid input parameter for sfifo_in\n");
		return -1;
	}
	if(ps->tail >= ps->head) {
		ps->freen = MAX_ENTRY - (ps->tail - ps->head);
	}
	else {
		ps->freen = MAX_ENTRY - (ps->head - ps->tail);
	}
	//full?
	if(ps->freen == 0) {
		return -1;
	}

	ps->entry_arr[ps->tail].pdata = buff;
	ps->entry_arr[ps->tail].size = sz;

	smp_wmb();
	ps->tail = (ps->tail + 1) % MAX_ENTRY;

	return 0;
}

/*sf input sfifo, buff is output parameter, return buff size*/
int sfifo_out(struct sfifo *sf, struct entry *ep)
{
	if(sf == NULL || ep == NULL) {
		printf("invalid sfifo out parameter\n");
		return -1;
	}
	//empty?
	if(sf->head == sf->tail) {
		return -1;
	}
	ep->pdata = sf->entry_arr[sf->head].pdata;
	ep->size  = sf->entry_arr[sf->head].size;	

	smp_wmb();
	sf->head = (sf->head + 1)%MAX_ENTRY;

	return 0;
}

#if 0
void *thd1_func(void *arg)
{
	struct sfifo *pf = (struct sfifo *)arg;
	char *pd = calloc(4096, 1);
	memset(pd, 0x88, 4096);
	int ret = -1;

	ret = sfifo_in(pf, pd, 4096);
	
	struct entry en = {.pdata = NULL, .size = 0,};
	
	while(1){
		int ret = sfifo_out(pf,&en);
		if(ret == 0) {
			printf("1: get out size:%d\n", en.size);
		}
	}
	
	return NULL;
}

void *thd2_func(void *arg)
{
	struct sfifo *pf = (struct sfifo *)arg;

	int i = 1;
	while(1) {
		i ++;
		if(i > 4) i = 1;
		int sz = i  * 1024;
		char *pd = calloc(sz, 1);
		memset(pd, 0x88, sz);
		printf("2 sfifo_in: size: %d\n ", sz);
		sfifo_in(pf, pd, sz);
	}
	return NULL;
}



int main()
{
	pthread_t thd1, thd2;
	struct sfifo *nf = sfifo_create();
	
	void *data = calloc(1024, 1);
	memset(data, 0x99, 1024);

	struct entry tmp = {.pdata = 0, .size = 0,};
	
	pthread_create(&thd1, NULL, thd1_func, nf);
	pthread_create(&thd2, NULL, thd2_func, nf);
	
	while(1)
        {
                sfifo_in(nf, data, 1024);

                sfifo_out(nf, &tmp);
                printf("main: out size:%d\n", tmp.size);
        }

	pthread_join(thd1, NULL);
	pthread_join(thd2, NULL);
	
	return 0;
}
#endif
