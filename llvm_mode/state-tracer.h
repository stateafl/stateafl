#ifndef _H_STATE_TRACER_
#define _H_STATE_TRACER_

#define SHM_STATE_ENV_VAR "STATE_SHM_ID"

#define MVP_RADIUS_ENV_VAR "MVP_RADIUS"
#define MVP_CALIBRATION_ENV_VAR "MVP_CALIBRATION_SHM_ID"
#define AFL_OUTDIR_ENV_VAR "AFL_OUTDIR"

#define MIN_STACK_ALLOC_SIZE 64

#define TLSH_SIZE 72

#define MAX_NUM_STATES 100
#define MAX_REPETITIONS 1000

#define RATE_LIMIT 5

struct state_shared {
    unsigned int seq_len;
    unsigned int seq[MAX_NUM_STATES];
    unsigned int iterations;
};

enum { TRACER_IDLE, TRACER_ANALYZING, TRACER_DONE };

struct calibration {

    /* Set to 1 to turn on calibration */
    int enabled;

    /* Sequence of hashes from the first calibration execution */
    int initialized;
    int ref_len;
    char ref_state_seq[MAX_NUM_STATES][TLSH_SIZE+1];

    /* TLSH distances between the first execution and the subsequent ones */
    int dist_len;
    int dist[MAX_NUM_STATES*MAX_REPETITIONS];

    /* TLSH distance for MVP radius */
    int mvp_radius;

    /* Rate limiting to prevent state explosion */
    int rate_limit;
};

#endif
