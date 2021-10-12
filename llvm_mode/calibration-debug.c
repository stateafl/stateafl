#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "state-tracer.h"

int main(int argc, char** argv) {

    if(argc < 2) {

      fprintf(stderr, "Usage: %s <shm-id>\n", argv[0]);
      exit(1);
    }


    int id;

    errno = 0;
    id = strtol(argv[1], NULL, 10);

    if(errno != 0) {
      fprintf(stderr, "Usage: %s <shm-id>\n", argv[0]);
      exit(1);
    }


    struct calibration * p = shmat(id, NULL, 0);

    if(p == (void*)-1) {
      fprintf(stderr, "Unable to attach to shared memory\n");
      exit(1);
    }

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

    printf("RADIUS: %d\n", p->mvp_radius);
}

