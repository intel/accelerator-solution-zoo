#ifndef __SFIFO_H
#define __SFIFO_H

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

struct sfifo *sfifo_create();
void sfifo_free(struct sfifo *ps);
int sfifo_in(struct sfifo *ps, void *buff, int sz);
int sfifo_out(struct sfifo *sf, struct entry *ep);

#endif
