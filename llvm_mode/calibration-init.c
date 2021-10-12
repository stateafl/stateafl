#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdio.h>

#include "state-tracer.h"

int main() {

    int id;

    id = shmget(ftok(".",'a'), sizeof(struct calibration), IPC_CREAT|IPC_EXCL|0644);

    if(id < 0) {

        id = shmget(ftok(".",'a'), sizeof(struct calibration), IPC_CREAT|0644);

        struct calibration * p = shmat(id, NULL, 0);

        printf("REFERENCE LENGTH: %d\n", p->ref_len);

        for(int i=0; i < p->ref_len; i++) {

            printf("[%d] %s\n", i, p->ref_state_seq[i]);
        }

        printf("\nDISTANCE LENGTH: %d\n", p->dist_len);

        for(int i=0; i < p->dist_len; i++) {

            printf("%d ", p->dist[i]);

            if( ((i+1) % p->ref_len) == 0 ) {
                printf("\n");
            }
        }

        printf("\n");

    } else {

        // new struct
        struct calibration * p = shmat(id, NULL, 0);

        p->initialized = 0;
        p->ref_len = 0;
        p->dist_len = 0;

    }

    printf("SHM ID: %d\n", id);
}
