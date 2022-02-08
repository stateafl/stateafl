#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <execinfo.h>
#include <errno.h>
#include <limits.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <pthread.h>

#include "../config.h"
#include "../types.h"

#include "state-tracer.h"

#include "containers.h"
#include "tlsh-wrapper.h"
#include "mvptree.h"

#define MVP_BRANCHFACTOR 2
#define MVP_PATHLENGTH   5
#define MVP_LEAFCAP    200

// TLSH distance for MVP NN search
#ifndef MVP_RADIUS
#define MVP_RADIUS 100
#endif

// TLSH distance for searching closest non-match
#define MVP_RADIUS_CLOSEST 10000

#define TLSH_SHOWVERS 1


#define LOG_FILE "state-tracer-rt.log"

//#define DEBUG_LOG_LEVEL
//#define INFO_LOG_LEVEL
//#define TIMING_LOG_LEVEL
//#define DEBUG_ALLOC


#if defined(LOG_FILE) && (defined(TIMING_LOG_LEVEL) || defined(INFO_LOG_LEVEL) || defined(DEBUG_LOG_LEVEL))
  #define LOG_FILE_ENABLED
  static FILE * __log_fd;
#endif

#if defined(LOG_FILE) && defined(DEBUG_LOG_LEVEL)
    #define LOG_DEBUG(...) fprintf(__log_fd, __VA_ARGS__); fflush(__log_fd);
#else
    #define LOG_DEBUG(...) do {} while (0)
#endif

#if defined(LOG_FILE) && (defined(INFO_LOG_LEVEL) || defined(DEBUG_LOG_LEVEL))
    #define LOG_INFO(...) fprintf(__log_fd, __VA_ARGS__)
#else
    #define LOG_INFO(...) do {} while (0)
#endif


#if defined(LOG_FILE_ENABLED) && (defined(TIMING_LOG_LEVEL) || defined(INFO_LOG_LEVEL) || defined(DEBUG_LOG_LEVEL)) && defined(ENABLE_TIMING)

#define START_TIMING(tracer) struct timeval t1, t2; double elapsedTime; gettimeofday(&t1, NULL);

#define END_TIMING(tracer) gettimeofday(&t2, NULL); elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0; elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0; fprintf(__log_fd,"ELAPSED " tracer ": %f ms\n", elapsedTime);

#else

#define START_TIMING(tracer)
#define END_TIMING(tracer)

#endif


static int __alloc_id = 0;
static int curr_iter_no = 0;

enum tracer_state { UNINITIALIZED, RECEIVING, SENDING };
static enum tracer_state curr_tracer_state = UNINITIALIZED;

struct alloc_record {
  int id;
  int iter_no_init;
  int iter_no_end;
  void * addr;
  size_t size;
  int freed;
  struct alloc_record * realloc;
#if defined(DEBUG_ALLOC) || defined(DEBUG_BACKTRACE)
  void * alloc_site;
#endif
};

struct alloc_dump {
  void * contents;
  struct alloc_record * record;
  int iter_no_dumped;
  size_t size;
};

static map alloc_records_map;
static queue alloc_dumps_queue;


/* Memory areas to ignore (e.g., I/O buffers) */
static map ignore_map;

struct ignore_area {
  void * addr;
  int size;
  struct alloc_record * record;
};


/* Tracking socket file descriptors */
static set sockets_set;

/* Pointer to shared memory */
/* The first integer contains the length of the sequence */
static struct state_shared * state_shared_ptr = NULL;

/* Radius for MVP tree nearest neighbour search */
static float mvp_radius_default = MVP_RADIUS;

/* Shared memory area for MVP radius calibration */
static struct calibration * calib_shm = NULL;

/* Directory for output files (set to AFL_OUTDIR) */
static char * out_dir = NULL;


#ifdef BLACKLIST_ALLOC_SITES

/* Black list for allocation sites */
static map alloc_blacklist_map;

#endif



/* Do not initialize stack memory if ASAN is enabled.
 * Enable "Stack Use After Return (UAR)" check to make ASAN initialize
 * stack memory by poisoning, see https://clang.llvm.org/docs/AddressSanitizer.html
 */
static int addr_san_detected = 0;




void init_state_tracer();
void end_state_tracer();

//#define ENABLE_TRACE_GLOBAL_DATA

#ifdef ENABLE_TRACE_GLOBAL_DATA
extern char __data_start, _edata;  // initialized data area
extern char __bss_start, _end;     // uninitialized data area
#endif


extern char __executable_start;
extern char __etext;


//#define __TRACER_USE_PTHREAD_MUTEX

#ifdef __TRACER_USE_PTHREAD_MUTEX
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif


static int compare_key_addr(const void * const one, const void * const two) {

  const void * a = *(void **)one;
  const void * b = *(void **)two;

  //LOG_DEBUG("COMPARE KEYS: a [%p] vs. b [%p]\n", a, b);

  if(a == b)
    return 0;
  else if(a < b)
    return -1;
  else
    return 1;
}

static int compare_int(const void *const one, const void *const two) {
    const int a = *(int *) one;
    const int b = *(int *) two;
    return a - b;
}


static Tlsh * __dist_t1;
static Tlsh * __dist_t2;

static float tlsh_distance(MVPDP *pointA, MVPDP *pointB){

    Tlsh_from_str(__dist_t1, pointA->data);
    Tlsh_from_str(__dist_t2, pointB->data);

    int diff = Tlsh_total_diff(__dist_t1, __dist_t2, 1/*len_diff*/);

    LOG_DEBUG("TLSH DISTANCE: %d\n", diff);

    return (float)diff;
}


#define INTERNAL_MEMCPY 1

#ifdef INTERNAL_MEMCPY

#define memcpy internal_memcpy

/* Custom memcpy implementation from XNU
 * https://opensource.apple.com/source/xnu/xnu-2050.7.9/libsyscall/wrappers/memcpy.c
 */

/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
typedef	int word;		/* "word" used for optimal copy speed */

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */

static
void * internal_memcpy(void *dst0, const void *src0, size_t length)
{
	char *dst = dst0;
	const char *src = src0;
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
		goto done;

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if ((unsigned long)dst < (unsigned long)src) {
		/*
		 * Copy forward.
		 */
		t = (uintptr_t)src;	/* only need low bits */
		if ((t | (uintptr_t)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (uintptr_t)dst) & wmask || length < wsize)
				t = length;
			else
				t = wsize - (t & wmask);
			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / wsize;
		TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		t = (uintptr_t)src;
		if ((t | (uintptr_t)dst) & wmask) {
			if ((t ^ (uintptr_t)dst) & wmask || length <= wsize)
				t = length;
			else
				t &= wmask;
			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
		TLOOP(src -= wsize; dst -= wsize; *(word *)dst = *(word *)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
done:
	return (dst0);
}

#endif



// Forces call to destructor on signal
static void tracer_signal_handler(__attribute__((unused)) const int signum) {
    LOG_DEBUG("Got signal (pid=%d)\n", getpid());
    exit(0);
}


__attribute__((constructor (0)))
void init_state_tracer() {

  char *out_dir_str = getenv(AFL_OUTDIR_ENV_VAR);

  struct stat s;
  if (out_dir_str && stat(out_dir_str,&s) == 0 && s.st_mode & S_IFDIR ) {

    // the var is a valid directory path
    out_dir = strdup(out_dir_str);

    LOG_INFO("OUTDIR: %s\n", out_dir_str);
  }
  else {

    // by default, save to CWD
    out_dir = strdup(".");
  }


#ifdef LOG_FILE_ENABLED
  char log_fname[PATH_MAX];
  snprintf(log_fname, PATH_MAX, "%s/%s", out_dir, LOG_FILE);
  __log_fd = fopen(log_fname, "a+");
#endif

  LOG_DEBUG("STATE TRACER STARTED\n");

  alloc_records_map = map_init(sizeof(void *), sizeof(struct alloc_record *), compare_key_addr);

  alloc_dumps_queue = queue_init(sizeof(struct alloc_dump));


  ignore_map = map_init(sizeof(void *), sizeof(struct ignore_area *), compare_key_addr);

  sockets_set = set_init(sizeof(int), compare_int);


  char *id_str = getenv(SHM_STATE_ENV_VAR);

  if (id_str) {

    LOG_DEBUG("SHM_STATE_ENV_VAR: %s\n", id_str);

    u32 shm_state_id = atoi(id_str);

    state_shared_ptr = shmat(shm_state_id, NULL, 0);

    if (state_shared_ptr == (void *)-1) {
      LOG_DEBUG("UNABLE TO ATTACH TO SHM (id=%d)\n", shm_state_id);
      _exit(1);
    }

    LOG_DEBUG("SHM STATE ID: %d\n", shm_state_id);
    LOG_DEBUG("SHM SHARED PTR: %p\n", state_shared_ptr);

  }
  else {

    // For testing
    state_shared_ptr = malloc(sizeof(struct state_shared));

    LOG_DEBUG("NO SHM (for testing)\n");
  }


  char *calib_str = getenv(MVP_CALIBRATION_ENV_VAR);

  if(calib_str) {

    LOG_DEBUG("CALIBRATION: %s\n", calib_str);

    u32 calib_shm_id = atoi(calib_str);

    calib_shm = shmat(calib_shm_id, NULL, 0);

    if (calib_shm == (void *)-1) {
      LOG_DEBUG("UNABLE TO ATTACH TO SHM FOR CALIBRATION (id=%d)\n", calib_shm_id);
      _exit(1);
    }

  }

  // Set initial state sequence length to 1 (first int)
  //state_shared_ptr->seq_len = 1;

  // Set initial state to 0 (dummy value)
  //state_shared_ptr->seq[0] = 0;


  signal(SIGTERM, tracer_signal_handler);
  signal(SIGINT, tracer_signal_handler);


#ifdef BLACKLIST_ALLOC_SITES
  char* blacklist_alloc_sites = getenv("BLACKLIST_ALLOC_SITES");

  alloc_blacklist_map = map_init(sizeof(void *), sizeof(void *), compare_key_addr);

  if(blacklist_alloc_sites) {

    LOG_DEBUG("BLACKLIST_ALLOC_SITES: %s\n", blacklist_alloc_sites);

    char * tokenizer = strdup(blacklist_alloc_sites);

    char* saveptr_blacklist = NULL;
    char* site = strtok_r(tokenizer, ":", &saveptr_blacklist);
    char *endptr = NULL;

    while(site) {

      // Split the item with format "0xADDRESS-SIZE" (e.g. "0x11223344-123")

      char* saveptr_item = NULL;
      char* addr_str = strtok_r(site, "-", &saveptr_item);

      void * site_addr_start = (void *)strtol(addr_str, &endptr, 16);

      if(endptr != NULL && *endptr != '\0') {
        LOG_DEBUG("INVALID BLACKLIST_ALLOC_SITES\n");
        goto next_item_alloc;
      }


      void * site_addr_end = site_addr_start;

      char* size_str = strtok_r(NULL, "-", &saveptr_item);

      if(size_str) {

        long site_size = strtol(size_str, &endptr, 16);

        site_addr_end += site_size;
      }


      LOG_DEBUG("ADDING ALLOC SITE TO BLACKLIST: [%p, %p]\n", site_addr_start, site_addr_end);

      map_put( alloc_blacklist_map, &site_addr_start, &site_addr_end );

next_item_alloc:
      site = strtok_r(0, ":", &saveptr_blacklist);
    }

    free(tokenizer);
  }
#endif

#ifdef ENABLE_TRACE_GLOBAL_DATA

  LOG_DEBUG("DATA AREA: %p - %p\n", &__data_start, &_edata);
  LOG_DEBUG("BSS AREA: %p - %p\n", &__bss_start, &_end);

  struct alloc_record * record_data = malloc(sizeof(struct alloc_record));

  record_data->id = __alloc_id++;
  record_data->iter_no_init = curr_iter_no;
  record_data->iter_no_end = -1;
  record_data->addr = &__data_start;
  record_data->size = &_edata - &__data_start;
  record_data->freed = 0;
  record_data->realloc = NULL;

  map_put( alloc_records_map, &__data_start, &record_data );

  struct alloc_record * record_bss = malloc(sizeof(struct alloc_record));

  record_bss->id = __alloc_id++;
  record_bss->iter_no_init = curr_iter_no;
  record_bss->iter_no_end = -1;
  record_bss->addr = &__bss_start;
  record_bss->size = &_end - &__bss_start;
  record_bss->freed = 0;
  record_bss->realloc = NULL;

  map_put( alloc_records_map, &__bss_start, &record_bss );

#ifdef BLACKLIST_GLOBALS

  char* blacklist_globals = getenv("BLACKLIST_GLOBALS");

  if(blacklist_globals) {

    LOG_DEBUG("BLACKLIST_GLOBALS: %s\n", blacklist_globals);

    char * tokenizer = strdup(blacklist_globals);

    char* saveptr_blacklist = NULL;
    char* item = strtok_r(tokenizer, ":", &saveptr_blacklist);

    while(item) {

      // Split the item with format "0xADDRESS-SIZE" (e.g. "0x11223344-123")

      char* saveptr_item = NULL;
      char* addr_str = strtok_r(item, "-", &saveptr_item);

      char *endptr = NULL;
      void * var_addr = (void *)strtol(addr_str, &endptr, 16);

      if(endptr != NULL && *endptr != '\0') {
        LOG_DEBUG("INVALID GLOBAL ADDR: %s\n", addr_str);
        goto next_item_global;
      }

      char* size_str = strtok_r(NULL, "-", &saveptr_item);
      long var_size = strtol(size_str, &endptr, 16);

      if(endptr != NULL && *endptr != '\0') {
        LOG_DEBUG("INVALID GLOBAL SIZE: %s\n", size_str);
        goto next_item_global;
      }


      LOG_DEBUG("ADDING GLOBAL VAR TO BLACKLIST: %p (size=%ld)\n", var_addr, var_size);


      struct ignore_area * ignore = malloc(sizeof(struct ignore_area));

      ignore->addr = var_addr;
      ignore->size = var_size;

      if(var_addr >= (void*)&__data_start && var_addr <= (void*)&_edata) {

        ignore->record = record_data;

      } else if(var_addr >= (void*)&__bss_start && var_addr <= (void*)&_end) {

        ignore->record = record_bss;

      } else {
        LOG_DEBUG("INVALID ADDRESS, NOT GLOBAL: %p\n", var_addr);
        goto next_item_global;
      }

      map_put( ignore_map, &var_addr, &ignore );

next_item_global:
      item = strtok_r(NULL, ":", &saveptr_blacklist);
    }

    free(tokenizer);
  }

#endif
#endif /* ENABLE_TRACE_GLOBAL_DATA */


  char *mvp_str = getenv(MVP_RADIUS_ENV_VAR);

  if (mvp_str) {

    LOG_DEBUG("MVP_RADIUS FROM ENV VAR: %s\n", mvp_str);

    mvp_radius_default = atoi(mvp_str);
  }


  if(getenv("AFL_USE_ASAN") || getenv("ASAN_OPTIONS")) {

    LOG_DEBUG("ASAN DETECTED\n");

    addr_san_detected = 1;
  }

}


#if defined(DEBUG_ALLOC) || defined(DEBUG_BACKTRACE)

static void * get_backtrace(void) {

#define BACKTRACE_DEPTH 15

  void *array[BACKTRACE_DEPTH];
  char **strings;
  int size, i;

  void *alloc_site = NULL;


  size = backtrace(array, BACKTRACE_DEPTH);

  if(size > 1) {
    i = 0;
    while(i < size && alloc_site == NULL) {

      if(array[i] < (void*)init_state_tracer || array[i] > (void*)end_state_tracer) {
#ifndef BACKTRACE_OFFSET
        alloc_site = array[i];
#else
        alloc_site = array[i + BACKTRACE_OFFSET];
#endif
      }

      i++;
    }
  }


#if (defined(INFO_LOG_LEVEL) || defined(DEBUG_LOG_LEVEL))

  strings = backtrace_symbols(array, size);

  if (strings != NULL) {

    LOG_DEBUG("Obtained %d stack frames.\n", size);
    for (i = 0; i < size; i++)
      LOG_DEBUG("%s\n", strings[i]);
  }

  free(strings);

#endif


  return alloc_site;
}
#endif


#ifdef RESTRICT_TEXT_ALLOCS

#define BACKTRACE_DEPTH_FOR_TEXT 6

static int check_text_alloc() {

  void *array[BACKTRACE_DEPTH_FOR_TEXT];
  int size, i;

  void *alloc_site = NULL;


  size = backtrace(array, BACKTRACE_DEPTH_FOR_TEXT);

  if(size > 1) {
    i = 0;
    while(i < size) {

      if(array[i] < (void*)init_state_tracer || array[i] > (void*)end_state_tracer) {

        alloc_site = array[i];

        LOG_DEBUG("CHECKING TEXT ALLOC: %p\n", alloc_site);

        if( alloc_site < (void*)&__executable_start || alloc_site > (void*)&__etext ) {

          LOG_DEBUG("ALLOC SITE OUTSIDE TEXT SEGMENT: %p\n", alloc_site);
          return 1;
        }
      }

      i++;
    }
  }

  return 0;

}
#endif

#ifdef BLACKLIST_ALLOC_SITES

static int check_blacklist() {

#define BACKTRACE_DEPTH 15

  void *array[BACKTRACE_DEPTH];
  int size, i;

  void *alloc_site = NULL;


  size = backtrace(array, BACKTRACE_DEPTH);

  if(size > 1) {
    i = 0;
    while(i < size) {

      if(array[i] < (void*)init_state_tracer || array[i] > (void*)end_state_tracer) {

        alloc_site = array[i];

        LOG_DEBUG("CHECKING BLACKLIST: %p\n", alloc_site);

        void** start_addr = map_floor(alloc_blacklist_map, &alloc_site);

        if( start_addr != NULL ) {

          void * end_addr = NULL;
          int found = map_get(&end_addr, alloc_blacklist_map, start_addr);

          if( found && alloc_site <= end_addr ) {

            LOG_DEBUG("ALLOC SITE FOUND IN BLACKLIST: %p\n", alloc_site);
            return 1;
          }
        }
      }

      i++;
    }
  }

  return 0;
}
#endif


void new_alloc_record(void * addr, size_t size) {

  START_TIMING("alloc");


  if(curr_iter_no > 0)
    return;   /* Skip allocations after the first request/reply iteration */


#ifdef BLACKLIST_ALLOC_SITES

  int blacklisted = check_blacklist();

  if(blacklisted)
    return;   /* Skip if the stack trace contains a blacklisted address */

#endif

#ifdef RESTRICT_TEXT_ALLOCS

  int non_text = check_text_alloc();

  if(non_text)
    return;   /* Skip if the allocation has not been made from the text segment of the executable (e.g., dynamic libs) */

#endif


  struct alloc_record * record = malloc(sizeof(struct alloc_record));

  record->id = __alloc_id++;
  record->iter_no_init = curr_iter_no;
  record->iter_no_end = -1;
  record->addr = addr;
  record->size = size;
  record->freed = 0;
  record->realloc = NULL;

  LOG_DEBUG("NEW ALLOC [%d]: %p, %lu\n", record->id, record->addr, record->size);

#if defined(DEBUG_ALLOC) || defined(DEBUG_BACKTRACE)
  record->alloc_site = get_backtrace();
#endif

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_lock(&mutex);
#endif

  map_put( alloc_records_map, &addr, &record );

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_unlock(&mutex);
#endif

  END_TIMING("alloc");
}

void free_alloc_record(void * addr) {

  START_TIMING("free");


  struct alloc_record * record;

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_lock(&mutex);
#endif

  int found = map_get(&record, alloc_records_map, &addr);

  if(found && record->freed == 0) {

    LOG_DEBUG("FREE ALLOC [%d]: %p\n", record->id, addr);

    record->iter_no_end = curr_iter_no;

    //map_remove(alloc_records_map, &addr);
    record->freed = 1;
  }

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_unlock(&mutex);
#endif

  END_TIMING("free");
}


void new_heap_alloc_record(void * addr, uint64_t size) {

  LOG_DEBUG("NEW HEAP ALLOC: %p (%lu bytes)\n", addr, size);

  if(!addr_san_detected) {

    // Zero-byte initialization of the area
    memset(addr, 0, size);
  }

  new_alloc_record(addr, size);
}

void free_heap_alloc_record(void * addr, uint64_t size) {

  LOG_DEBUG("FREE HEAP ALLOC: %p (%lu bytes)\n", addr, size);

  free_alloc_record(addr);
}

void new_stack_alloc_record(void * addr, uint64_t size) {

  LOG_DEBUG("NEW STACK ALLOC: %p (%lu bytes)\n", addr, size);

  if(!addr_san_detected) {

    // Zero-byte initialization of the area
    memset(addr, 0, size);
  }

  new_alloc_record(addr, size);
}

void free_stack_alloc_record(void * addr, uint64_t size) {

  LOG_DEBUG("FREE STACK ALLOC: %p (%lu bytes)\n", addr, size);

  free_alloc_record(addr);
}

void trace_calloc(void * addr, int size, int nmemb) {

  LOG_DEBUG("NEW HEAP CALLOC: %p (%d elems, %lu bytes)\n", addr, nmemb, size*nmemb);

  if(!addr_san_detected) {

    // Zero-byte initialization of the area
    memset(addr, 0, size*nmemb);
  }

  new_alloc_record(addr, size*nmemb);
}

void trace_realloc(void * addr, int size, void * oldaddr) {

  LOG_DEBUG("TRACE REALLOC\n");

  START_TIMING("alloc");

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_lock(&mutex);
#endif

  struct alloc_record * record_oldalloc = NULL;

  int found = map_get(&record_oldalloc, alloc_records_map, &oldaddr);

#ifdef __TRACER_USE_PTHREAD_MUTEX
    pthread_mutex_unlock(&mutex);
#endif


  int oldalloc_iter_no = -1;
  int oldalloc_size = 0;

  if(found) {

    oldalloc_iter_no = record_oldalloc->iter_no_init;
    oldalloc_size = record_oldalloc->size;

    if(size > oldalloc_size) {
      // Zero-byte initialization of the area
      memset(addr + oldalloc_size, 0, size - oldalloc_size);
    }
  }



#ifdef BLACKLIST_ALLOC_SITES

  int blacklisted = check_blacklist();

  if(blacklisted)
    return;   /* Skip if the stack trace contains a blacklisted address */

#endif

#ifdef RESTRICT_TEXT_ALLOCS

  int non_text = check_text_alloc();

  if(non_text)
    return;   /* Skip if the allocation has not been made from the text segment of the executable (e.g., dynamic libs) */

#endif


  if((!found && curr_iter_no > 0) || oldalloc_iter_no > 0) {
    return;
  }


  if( addr == oldaddr ) {

    if(found)
      record_oldalloc->size = size;

  } else {

    // addr != oldaddr

    free_alloc_record(oldaddr);

    struct alloc_record * record = malloc(sizeof(struct alloc_record));

    record->id = __alloc_id++;
    record->iter_no_init = oldalloc_iter_no;
    record->iter_no_end = -1;
    record->addr = addr;
    record->size = size;
    record->freed = 0;
    record->realloc = NULL;

    if(found)
      record_oldalloc->realloc = record;

    LOG_DEBUG("NEW ALLOC [%d]: %p, %lu\n", record->id, record->addr, record->size);

#if defined(DEBUG_ALLOC) || defined(DEBUG_BACKTRACE)
    record->alloc_site = get_backtrace();
#endif

#ifdef __TRACER_USE_PTHREAD_MUTEX
    pthread_mutex_lock(&mutex);
#endif

    map_put( alloc_records_map, &addr, &record );

#ifdef __TRACER_USE_PTHREAD_MUTEX
    pthread_mutex_unlock(&mutex);
#endif

  }


  END_TIMING("alloc");
}

static void tracer_dump() {

  START_TIMING("dump");

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_lock(&mutex);
#endif


  void ** key = map_first(alloc_records_map);

  while( key != NULL ) {

    struct alloc_record * record;

    int found = map_get(&record, alloc_records_map, key);

    if(found && record->freed == 0) {

      LOG_DEBUG("DUMPING ALLOC RECORD [%d]: addr=%p (size=%lu bytes)\n", record->id, record->addr, record->size);

      struct alloc_dump dump;
      dump.iter_no_dumped = curr_iter_no;
      dump.record = record;
      dump.contents = malloc(record->size);
      dump.size = record->size;
      memcpy(dump.contents, record->addr, record->size);

      queue_push(alloc_dumps_queue, &dump);

    }

    key = map_higher(alloc_records_map, key);

  }

#ifdef __TRACER_USE_PTHREAD_MUTEX
  pthread_mutex_unlock(&mutex);
#endif

  END_TIMING("dump");
}



static int is_socket(int fd) {

    int is_socket = 0;
    int socket_type;
    socklen_t length = sizeof(socket_type);


    if( set_contains(sockets_set, &fd) == BK_TRUE ) {

        LOG_DEBUG("FD IN SOCKET SET\n");

        is_socket = 1;
    }
    else if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &length) != -1) {

        LOG_DEBUG("FD IS SOCKET\n");

        is_socket = 1;

        set_put(sockets_set, &fd);

    } else {

        LOG_DEBUG("FD IS NOT SOCKET\n");

        if(errno != ENOTSOCK)
            LOG_DEBUG("Unexpected error with getsockopt()!\n");
    }

    return is_socket;
}

struct alloc_record * check_inner_pointer(void * buf) {

  struct alloc_record * record = NULL;

  void ** floor_key = map_floor(alloc_records_map, &buf);

  if(floor_key == NULL) return NULL;

  //LOG_DEBUG("check inner pointer: floor_key = %p\n", *floor_key);

  int found = map_get(&record, alloc_records_map, floor_key);

  //LOG_DEBUG("check inner pointer: found = %d, addr = %p (%d)\n", found, record->addr, record->size);

  if(found && buf <= record->addr+record->size)
    return record;

  return NULL;
}

void check_iobuf(void * buf, size_t size) {

  struct ignore_area * iobuf;
  int found = map_get(&iobuf, ignore_map, &buf);

  if(!found) {

    struct alloc_record * record = check_inner_pointer(buf);

    if(record != NULL && record->freed == 0) {
      LOG_DEBUG("DETECTED I/O BUF AREA: addr = %p, size = %ld\n", buf, size);

      iobuf = malloc(sizeof(struct ignore_area));

      iobuf->addr = buf;
      iobuf->size = size;
      iobuf->record = record;

      map_put( ignore_map, &buf, &iobuf );

    }
  }

}


static void net_receive(void * buf, int size) {

  LOG_DEBUG("TRACE RECV (buf = %p, size = %d)\n", buf, size);

  if(curr_tracer_state == UNINITIALIZED)
    curr_tracer_state = RECEIVING;

  if(curr_tracer_state == SENDING) {
    curr_tracer_state = RECEIVING;
  }

  check_iobuf(buf, size);
}

static void net_send(void * buf, int size) {

  LOG_DEBUG("TRACE SEND (buf = %p, size = %d)\n", buf, size);

  if(curr_tracer_state == UNINITIALIZED)
    curr_tracer_state = SENDING;

  if(curr_tracer_state == RECEIVING) {
    curr_tracer_state = SENDING;
    tracer_dump();
    curr_iter_no++;
  }

  check_iobuf(buf, size);
}

void trace_receive(void * buf, int size) {

  START_TIMING("recv");

  net_receive(buf, size);

  END_TIMING("recv");
}

void trace_send(void * buf, int size) {

  START_TIMING("send");

  net_send(buf, size);

  END_TIMING("send");
}



void trace_read(int fd, void * buf, int size) {

  LOG_DEBUG("TRACE READ\n");

  START_TIMING("read");

  if(is_socket(fd)) {
      net_receive(buf, size);
  }

  END_TIMING("read");
}

void trace_write(int fd, void * buf, int size) {

  LOG_DEBUG("TRACE WRITE\n");

  START_TIMING("write");

  if(is_socket(fd)) {
      net_send(buf, size);
  }

  END_TIMING("write");
}

void trace_fprintf(void* p, void * buf, int size) {

  LOG_DEBUG("TRACE FPRINTF\n");

  START_TIMING("fprintf");

  FILE * stream = p;
  int fd = fileno(stream);

  if(fd == -1) {
    LOG_DEBUG("INVALID STREAM\n");
    return;
  }

  if(is_socket(fd)) {
    net_send(buf, size);
  }

  END_TIMING("fprintf");
}

void trace_fgets(void* p, void * buf, int size) {

  LOG_DEBUG("TRACE FGETS\n");

  START_TIMING("fgets");

  FILE * stream = p;
  int fd = fileno(stream);

  if(fd == -1) {
    LOG_DEBUG("INVALID STREAM\n");
    return;
  }

  if(is_socket(fd)) {
    net_receive(buf, size);
  }

  END_TIMING("fgets");
}

void trace_fread(void* p, void * buf, int size, int nmemb) {

  LOG_DEBUG("TRACE FREAD\n");

  START_TIMING("fread");

  FILE * stream = p;
  int fd = fileno(stream);

  if(fd == -1) {
    LOG_DEBUG("INVALID STREAM\n");
    return;
  }

  if(is_socket(fd)) {
    net_receive(buf, size*nmemb);
  }

  END_TIMING("fread");
}

void trace_fwrite(void* p, void * buf, int size, int nmemb) {

  LOG_DEBUG("TRACE FWRITE\n");

  START_TIMING("fwrite");

  FILE * stream = p;
  int fd = fileno(stream);

  if(fd == -1) {
    LOG_DEBUG("INVALID STREAM\n");
    return;
  }

  if(is_socket(fd)) {
    net_send(buf, size*nmemb);
  }

  END_TIMING("fwrite");
}

void trace_close(int fd) {

  LOG_DEBUG("TRACE CLOSE\n");

  START_TIMING("close");

  if(is_socket(fd)) {

    set_remove(sockets_set, &fd);
  }

#ifdef LOG_FILE_ENABLED
  if(fd == fileno(__log_fd)) {

    /* Re-open the log file if it was accidentally closed by the target */
    __log_fd = fopen(LOG_FILE, "a+");
  }
#endif

  END_TIMING("close");
}

void trace_fclose(FILE * p) {

  LOG_DEBUG("TRACE FCLOSE\n");

  FILE * stream = p;
  int fd = fileno(stream);

  if(fd == -1) {
    LOG_DEBUG("INVALID STREAM\n");
    return;
  }

  trace_close(fd);
}


static int new_state_found = 0;

unsigned int compute_state_value(Tlsh * t, int data_size, MVPTree * tree, unsigned int * unique_states, unsigned int current_state_number) {

  unsigned int computed_state = 0;


#define MIN_DATA_SIZE 1024

  if(data_size < MIN_DATA_SIZE) {

    // Add more randomness for small buffers

    LOG_DEBUG("ADDING MORE RANDOMNESS (initial size=%d)\n", data_size);

    char buffer[MIN_DATA_SIZE];

    for(int i=0; i<MIN_DATA_SIZE-data_size; i++) {

      buffer[i] = i % 26 + 'A';
    }

    Tlsh_update(t, buffer, MIN_DATA_SIZE - data_size);

    data_size = MIN_DATA_SIZE;
  }


  Tlsh_final(t, NULL, 0, 0);

  const char * tlsh_hash = Tlsh_get_hash(t, TLSH_SHOWVERS);

  LOG_DEBUG("TLSH HASH: '%s'\n", tlsh_hash);
  LOG_DEBUG("DATA SIZE: %d\n", data_size);


  // Under calibration
  if(calib_shm && calib_shm->enabled == 1) {

    if(calib_shm->initialized == 0) {

      LOG_DEBUG("APPENDING HASH TO REFERENCE SEQUENCE FOR CALIBRATION: %d\n", calib_shm->ref_len);

      strcpy(calib_shm->ref_state_seq[calib_shm->ref_len], tlsh_hash);
      calib_shm->ref_len++;
    }
    else {

      //int current_state_number = state_shared_ptr->seq_len - 1;

      if(current_state_number <= calib_shm->ref_len) {

        Tlsh * ref_tlsh = Tlsh_new();

        Tlsh_from_str(ref_tlsh, calib_shm->ref_state_seq[current_state_number]);

        int diff = Tlsh_total_diff(ref_tlsh, t, 1/*len_diff*/);

        LOG_DEBUG("TLSH DISTANCE FROM REF: %d\n", diff);

        calib_shm->dist[calib_shm->dist_len] = diff;
        calib_shm->dist_len++;

        Tlsh_delete(ref_tlsh);
      }
    }

    LOG_DEBUG("COMPUTE STATE: NULL\n");
    return 0;
  }




  MVPError err;

  MVPDP *mvp_node = dp_alloc(BYTEARRAY);
  mvp_node->data = strdup(tlsh_hash);
  mvp_node->datalen = TLSH_SIZE+1;
  mvp_node->id = strdup("query");

  unsigned int knearest = 1;
  unsigned int nbresults = 0;


  float mvp_radius = mvp_radius_default;

  if(calib_shm) {
    mvp_radius = (float)calib_shm->mvp_radius;
  }

  LOG_DEBUG("MVP RADIUS: %f\n", mvp_radius);


  MVPDP **results = mvptree_retrieve(tree, mvp_node, knearest, mvp_radius, &nbresults, &err);

  if( nbresults > 0 && (err == MVP_SUCCESS || err == MVP_KNEARESTCAP) ) {

#if defined(LOG_FILE) && defined(DEBUG_LOG_LEVEL)

    LOG_DEBUG("QUERY MVP TREE - HASH FOUND\n");

    for(int i=0; i < nbresults; i++) {

      const char * found_hash = results[i]->data;
      LOG_DEBUG("HASH FOUND: %s (id=%s, distance=%f)\n", found_hash, results[i]->id, tlsh_distance(results[i], mvp_node) );
    }

#endif

    computed_state = atoi(results[0]->id);

    dp_free(mvp_node, free);

  } else if( err != MVP_SUCCESS && err != MVP_KNEARESTCAP && err != MVP_EMPTYTREE ) {

    LOG_DEBUG("MVP QUERY ERROR: %d\n", err);

    dp_free(mvp_node, free);

  } else {

#if (defined(INFO_LOG_LEVEL) || defined(DEBUG_LOG_LEVEL))

    LOG_DEBUG("QUERY MVP TREE - HASH NOT FOUND\n");

    if(results)
      free(results);

    float radius = MVP_RADIUS_CLOSEST;
    results = mvptree_retrieve(tree, mvp_node, knearest, radius, &nbresults, &err);

    if( nbresults > 0 && (err == MVP_SUCCESS || err == MVP_KNEARESTCAP) ) {

      const char * found_hash = results[0]->data;
      float distance = tlsh_distance(results[0], mvp_node);

      LOG_INFO("QUERY HASH NOT FOUND: '%s'\n", tlsh_hash);
      LOG_INFO("NEAREST NON-MATCHED HASH: '%s' (id=%s, distance=%f)\n", found_hash, results[0]->id, distance);
    }
#endif


    char state_num[8];
    snprintf(state_num, 8, "%d", *unique_states+1);
    free(mvp_node->id);
    mvp_node->id = strdup(state_num);

    LOG_INFO("ADDING NEW HASH TO MVP TREE: state=%s, hash='%s' (size=%d)\n", mvp_node->id, (char*)mvp_node->data, mvp_node->datalen);

    err = mvptree_add(tree, &mvp_node, 1);

    if(err != MVP_SUCCESS) {
        LOG_DEBUG("MVPError: %d\n", err);
        exit(1);
    }

    *unique_states += 1;

    computed_state = *unique_states;

    new_state_found++;

  }

  if(results)
    free(results);

  LOG_DEBUG("COMPUTED STATE: %d\n", computed_state);

  return computed_state;
}



__attribute__((destructor))
void end_state_tracer() {

#ifdef SKIP_POSTEXEC_ANALYSIS
  LOG_DEBUG("Skipping analysis, terminating...\n");
  return;
#endif

  START_TIMING("end_state_tracer");

  int num_dumps = queue_size(alloc_dumps_queue);

  LOG_DEBUG("# DUMPS: %d\n\n", num_dumps);
  LOG_DEBUG("Latest iteration: %d\n", curr_iter_no);

  if(num_dumps == 0) {
    LOG_DEBUG("No dumps found, skipping analysis...\n");
    goto end_analysis;
  }


  unsigned int current_state_value = 0;
  unsigned int current_state_number = 0;
  unsigned int * state_sequence = state_shared_ptr->seq;

  // Set number of iterations to be computed
  // (for syncing with the fuzzer)
  state_shared_ptr->iterations = curr_iter_no;

  // Disarm signals while saving the state sequence
  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);


  // Initializing MVP Tree for state hashes

  char mvp_file[PATH_MAX];
  char unique_states_file[PATH_MAX];
  snprintf(mvp_file, PATH_MAX, "%s/.tree.mvp", out_dir);
  snprintf(unique_states_file, PATH_MAX, "%s/.tree.count.mvp", out_dir);


  MVPError err = MVP_SUCCESS;
  MVPTree* tree = NULL;
  CmpFunc distance_func = tlsh_distance;

  unsigned int unique_states = 0;

  struct stat mvp_stat_record;
  if(stat(mvp_file, &mvp_stat_record) == 0 && mvp_stat_record.st_size > 1) {

    // The file exists and it is non-empty
    LOG_INFO("Reading MVP Tree from file (%s)...\n", mvp_file);
    tree = mvptree_read(mvp_file, distance_func, MVP_BRANCHFACTOR, MVP_PATHLENGTH, MVP_LEAFCAP, &err);
  }

  if(err != MVP_SUCCESS || tree == NULL) {

    LOG_INFO("Unable to read MVP Tree from file, initializing new one...\n");
    tree = mvptree_alloc(NULL, distance_func, MVP_BRANCHFACTOR, MVP_PATHLENGTH, MVP_LEAFCAP);

    if(tree == NULL) {
      LOG_DEBUG("UNABLE TO INITIALIZE NEW MVP TREE\n");
    }

  } else {

    LOG_DEBUG("MVP TREE LOADED\n");


    if( access( unique_states_file, R_OK|W_OK ) == 0 ) {

      // file exists
      FILE * fd_uniq_states = fopen(unique_states_file, "r");

      if(fd_uniq_states == NULL) {
        LOG_DEBUG("UNABLE TO OPEN %s (errno=%d)\n", unique_states_file, errno);
      }

      int r = fscanf(fd_uniq_states, "%d", &unique_states);

      if(r < 1) {
        LOG_DEBUG("UNABLE TO READ %s (r=%d)\n", unique_states_file, r);
      }

      LOG_DEBUG("UNIQUE STATES INITIALIZED: %d\n", unique_states);

      fclose(fd_uniq_states);

    } else {

      // file doesn't exist
      LOG_DEBUG("CANNOT FIND %s\n", unique_states_file);
    }

  }



  // Add initial state "zero"
  LOG_INFO("SAVING STATE [# 0]: 0\n");
  *state_sequence = 0;
  state_sequence++;
  current_state_number++;


  Tlsh * tlsh = Tlsh_new();
  int curr_state_buffer_data = 0;

  __dist_t1 = Tlsh_new();
  __dist_t2 = Tlsh_new();



  for(int i=0; i<num_dumps; i++) {

    struct alloc_dump dump;

    queue_pop(&dump, alloc_dumps_queue);

    LOG_DEBUG("\nDUMPING [%p, id=%d, iter_init=%d, iter_end=%d, iter_dumped=%d]:\n", dump.record->addr, dump.record->id, dump.record->iter_no_init, dump.record->iter_no_end, dump.iter_no_dumped);

    /*
    for(int row=0; row <= dump.record->size/8; row++) {
      for(int col=0; (col < 8) && (col+row*8 < dump.record->size); col++) {
        LOG_DEBUG(" %02x", ((char *)dump.contents)[col + row*8]);
      }
      LOG_DEBUG("\n");
    }
    LOG_DEBUG("\n");
    */


    // Skip transient areas

    int iter_no_init = dump.record->iter_no_init;
    int iter_no_end  = dump.record->iter_no_end;

    struct alloc_record * r = dump.record->realloc;
    while(r != NULL) {
      iter_no_end = r->iter_no_end;
      r = r->realloc;
    }

    if(dump.record->realloc != NULL)
      LOG_DEBUG("REALLOCD AREA: addr=%p, id=%d, iter_no_end=%d, iter_no_end reallc'd=%d\n", dump.record->addr, dump.record->id, dump.record->iter_no_end, iter_no_end);

    if( iter_no_init > 0 ||
        (iter_no_end < curr_iter_no && iter_no_end != -1) ) {

          LOG_DEBUG("SKIPPING TRANSIENT AREA: [%p, id=%d, iter_init=%d, iter_end=%d, iter_dumped=%d]:\n", dump.record->addr, dump.record->id, iter_no_init, iter_no_end, dump.iter_no_dumped);
          continue;
    }


    // Skip I/O buffers

    struct ignore_area * ignore_buf;
    int found = map_get(&ignore_buf, ignore_map, &dump.record->addr);

    if(found) {

      LOG_DEBUG("SKIPPING IGNORED AREA: [%p, id=%d, iter_init=%d, iter_end=%d, iter_dumped=%d]:\n", dump.record->addr, dump.record->id, iter_no_init, iter_no_end, dump.iter_no_dumped);

      continue;
    }


    // If dump with new iteration number is found,
    // save the current state value, and move on to the next state.

    // NOTE: Offset -1 because we added a dummy state "0" at the beginning

    if(current_state_number-1 < dump.iter_no_dumped) {

      current_state_value = compute_state_value(tlsh, curr_state_buffer_data, tree, &unique_states, current_state_number-1);

      Tlsh_reset(tlsh);
      curr_state_buffer_data = 0; // Reset accumulated size of dumps for the current iteration


      LOG_INFO("SAVING STATE [# %d]: %08x\n", current_state_number, current_state_value);

      *state_sequence = current_state_value;
      state_sequence++;
      current_state_number++;

      // update state sequence length
      state_shared_ptr->seq_len = current_state_number;

      current_state_value = 0;

    }


    // Checksumming heap data

    LOG_DEBUG("ANALYZING: [%p, id=%d, iter_init=%d, iter_end=%d, iter_dumped=%d, size=%ld]:\n", dump.record->addr, dump.record->id, iter_no_init, iter_no_end, dump.iter_no_dumped, dump.size);


#ifdef DEBUG_ALLOC

    char dump_fname[100];

    sprintf(dump_fname, "./dump-%d-%p-%d.log", dump.record->id, dump.record->alloc_site, dump.iter_no_dumped);

    FILE * fd_dump = fopen(dump_fname, "w+");

#endif

    // Append dump data to the current state buffer

    int dump_start = 0;
    int dump_size = 0;
    int dump_next_start = 0;

    void **closest_ignore_addr = map_higher(ignore_map, &dump.record->addr);
    struct ignore_area * closest_ignore = NULL;

    /* Skip ignore areas *within* the area
     * (e.g., an I/O buffer array inside a stack frame)
     *
     * See diagram:
     *

       addr     ignore1               ignore2
         │      │      ignore1+igsz1  │   ignore2+igsz2
         │      │      │              │   │         ┌────addr+
         ▼      ▼      ▼              ▼   ▼         ▼    size
         ┌──────┬──────┬─────────────┬────┬─────────┐
         │      │xxxxxx│             │xxxx│         │
         │      │xxxxxx│             │xxxx│         │
         │      │xxxxxx│             │xxxx│         │
         └──────┴──────┴─────────────┴────┴─────────┘
          size1             size2            size3
          ◄────►        ◄───────────►      ◄───────►
          addr           addr+size1+      addr+size1+
          ....             +igsz1        +igsz1+size2+
          addr+             ....            +igsz2
      +(ignore1-addr)       addr+            ....
                        +(ignore2-addr)      addr+
                                             size
     */

    while( closest_ignore_addr != NULL &&
           *closest_ignore_addr < dump.record->addr + dump.size ) {

      map_get( &closest_ignore, ignore_map, closest_ignore_addr );

      if( closest_ignore != NULL &&
          *closest_ignore_addr + closest_ignore->size <= dump.record->addr + dump.size &&
          *closest_ignore_addr >= dump.record->addr + dump_next_start &&
          dump.iter_no_dumped >= closest_ignore->record->iter_no_init &&	  // sanity checks
          (dump.iter_no_dumped <= closest_ignore->record->iter_no_end || closest_ignore->record->iter_no_end == -1)
        ) {

        LOG_DEBUG("SKIPPING IGNORED AREA INSIDE AREA: [area=%p, ignore_addr=%p, size=%d]\n", dump.record->addr, *closest_ignore_addr, closest_ignore->size);

        dump_start = dump_next_start;
        dump_size = (*closest_ignore_addr - dump.record->addr) - dump_start;
        dump_next_start = (*closest_ignore_addr - dump.record->addr) + closest_ignore->size;

        if( dump_size > 0 ) {
          LOG_DEBUG("STORING AREA: [start=%p, size=%d]\n", dump.record->addr + dump_start, dump_size);

          Tlsh_update(tlsh, dump.contents + dump_start, dump_size);
          curr_state_buffer_data += dump_size;

#ifdef DEBUG_ALLOC
          fwrite(dump.contents + dump_start, dump_size, 1, fd_dump);
#endif
        }

      }

      closest_ignore_addr = map_higher(ignore_map, closest_ignore_addr);
    }

    dump_start = dump_next_start;
    dump_size = dump.size - dump_next_start;

    if( dump_size > 0 ) {
      LOG_DEBUG("STORING AREA: [start=%p, size=%d]\n", dump.record->addr + dump_start, dump_size);

      Tlsh_update(tlsh, dump.contents + dump_start, dump_size);
      curr_state_buffer_data += dump_size;

#ifdef DEBUG_ALLOC
      fwrite(dump.contents + dump_start, dump_size, 1, fd_dump);
#endif
    }

#ifdef DEBUG_ALLOC
    fclose(fd_dump);
#endif

    free(dump.contents);

    if(dump.record->iter_no_end == dump.iter_no_dumped) {
      free(dump.record);
    }
  }

  // save the last state of the sequence
  current_state_value = compute_state_value(tlsh, curr_state_buffer_data, tree, &unique_states, current_state_number-1);
  *state_sequence = current_state_value;

  LOG_INFO("SAVING STATE [# %d]: %08x\n\n", current_state_number, current_state_value);


  // save the state sequence length
  state_shared_ptr->seq_len = current_state_number+1;

  LOG_DEBUG("TOTAL STATES: %d\n", state_shared_ptr->seq_len);



  // if calibration has been enabled, then the next runs will not initialize
  // again the reference state sequence
  if(calib_shm && calib_shm->enabled == 1) {
    calib_shm->initialized = 1;
  }


#ifndef DISABLE_RATE_LIMITING

  // Rate limiting to prevent state explosion

  if(calib_shm && calib_shm->enabled == 0) {

    if(new_state_found > 0) {
      LOG_INFO("INCREASE RATE COUNTER\n");

      calib_shm->rate_limit += new_state_found;
    }
    else {
      LOG_INFO("DECREASE RATE COUNTER\n");

      if( calib_shm->rate_limit > 1 )
        calib_shm->rate_limit--;
      else
        calib_shm->rate_limit = 0;
    }

    if(calib_shm->rate_limit >= RATE_LIMIT) {

      // If new states are found for RATE_LIMIT
      // consecutive times, increase threshold

      calib_shm->mvp_radius += 10;
      calib_shm->rate_limit = 0;

      LOG_INFO("RATE LIMIT HIT - INCREASE MVP RADIUS: %d\n", calib_shm->mvp_radius);


      char tlsh_file[PATH_MAX];
      snprintf(tlsh_file, PATH_MAX, "%s/tlsh.log", out_dir);

      FILE * fd_tlsh = fopen(tlsh_file, "a");
      fprintf(fd_tlsh, "%d\n", calib_shm->mvp_radius);
      fclose(fd_tlsh);

    }
  }
#endif


  // Store MVP Tree data
  // (unless calibration is enabled)

  if(!(calib_shm && calib_shm->enabled == 1)) {

    LOG_INFO("WRITING MVP TREE TO FILE (%s)...\n", mvp_file);
    err = mvptree_write(tree, mvp_file, 00777);

    if(err != MVP_SUCCESS) {
      LOG_INFO("UNABLE TO SAVE MVP TREE (err=%d)\n", err);
    }

    FILE * fd_uniq_states = fopen(unique_states_file, "w");

    if(fd_uniq_states == NULL) {
      LOG_DEBUG("UNABLE TO OPEN %s (errno=%d)\n", unique_states_file, errno);
    }

    int written = fprintf(fd_uniq_states, "%d", unique_states);

    if(written < 1) {
      LOG_DEBUG("UNABLE TO WRITE %s (written=%d)\n", unique_states_file, written);
    }

    fclose(fd_uniq_states);

  }

  mvptree_clear(tree, free);
  free(tree);

  Tlsh_delete(tlsh);
  Tlsh_delete(__dist_t1);
  Tlsh_delete(__dist_t2);


end_analysis:

  map_destroy(alloc_records_map);
  queue_destroy(alloc_dumps_queue);

  free(out_dir);


  END_TIMING("end_state_tracer");

#ifdef LOG_FILE_ENABLED
  fclose(__log_fd);
#endif
}
