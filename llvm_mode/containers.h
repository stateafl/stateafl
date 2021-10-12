/*
 * Copyright (c) 2017-2020 Bailey Thompson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * The Containers library is hosted at: github.com/bkthomps/Containers
 * The author is: Bailey Thompson
 * This local version is: v1.2.0
 */


#ifndef BKTHOMPS_CONTAINERS_ALL_H
#define BKTHOMPS_CONTAINERS_ALL_H

#include <stdlib.h>

/*
 * Cannot use <errno.h> because the C89 standard does not guarantee all
 * of these. These are the same values as the regular linux error codes.
 */
#define BK_OK 0
#define BK_ENOMEM 12
#define BK_EINVAL 22
#define BK_ERANGE 34

/* Cannot use <stdbool.h> because it is C99 not C89. */
#define BK_FALSE 0
#define BK_TRUE (!BK_FALSE)

typedef int bk_err;
typedef int bk_bool;

#endif /* BKTHOMPS_CONTAINERS_ALL_H */


#ifndef BKTHOMPS_CONTAINERS_ARRAY_H
#define BKTHOMPS_CONTAINERS_ARRAY_H

/**
 * The array data structure, which is a static contiguous array.
 */
typedef char *array;

/* Starting */
array array_init(size_t element_count, size_t data_size);

/* Utility */
size_t array_size(array me);
void array_copy_to_array(void *arr, array me);
void *array_get_data(array me);
bk_err array_add_all(array me, void *arr, size_t size);

/* Accessing */
bk_err array_set(array me, size_t index, void *data);
bk_err array_get(void *data, array me, size_t index);

/* Ending */
array array_destroy(array me);

#endif /* BKTHOMPS_CONTAINERS_ARRAY_H */


#ifndef BKTHOMPS_CONTAINERS_DEQUE_H
#define BKTHOMPS_CONTAINERS_DEQUE_H

/**
 * The deque data structure, which is a doubly-ended queue.
 */
typedef struct internal_deque *deque;

/* Starting */
deque deque_init(size_t data_size);

/* Utility */
size_t deque_size(deque me);
bk_bool deque_is_empty(deque me);
bk_err deque_trim(deque me);
void deque_copy_to_array(void *arr, deque me);
bk_err deque_add_all(deque me, void *arr, size_t size);

/* Adding */
bk_err deque_push_front(deque me, void *data);
bk_err deque_push_back(deque me, void *data);

/* Removing */
bk_err deque_pop_front(void *data, deque me);
bk_err deque_pop_back(void *data, deque me);

/* Setting */
bk_err deque_set_first(deque me, void *data);
bk_err deque_set_at(deque me, size_t index, void *data);
bk_err deque_set_last(deque me, void *data);

/* Getting */
bk_err deque_get_first(void *data, deque me);
bk_err deque_get_at(void *data, deque me, size_t index);
bk_err deque_get_last(void *data, deque me);

/* Ending */
bk_err deque_clear(deque me);
deque deque_destroy(deque me);

#endif /* BKTHOMPS_CONTAINERS_DEQUE_H */


#ifndef BKTHOMPS_CONTAINERS_FORWARD_LIST_H
#define BKTHOMPS_CONTAINERS_FORWARD_LIST_H

/**
 * The forward_list data structure, which is a singly-linked list.
 */
typedef struct internal_forward_list *forward_list;

/* Starting */
forward_list forward_list_init(size_t data_size);

/* Utility */
size_t forward_list_size(forward_list me);
bk_bool forward_list_is_empty(forward_list me);
void forward_list_copy_to_array(void *arr, forward_list me);
bk_err forward_list_add_all(forward_list me, void *arr, size_t size);

/* Adding */
bk_err forward_list_add_first(forward_list me, void *data);
bk_err forward_list_add_at(forward_list me, size_t index, void *data);
bk_err forward_list_add_last(forward_list me, void *data);

/* Removing */
bk_err forward_list_remove_first(forward_list me);
bk_err forward_list_remove_at(forward_list me, size_t index);
bk_err forward_list_remove_last(forward_list me);

/* Setting */
bk_err forward_list_set_first(forward_list me, void *data);
bk_err forward_list_set_at(forward_list me, size_t index, void *data);
bk_err forward_list_set_last(forward_list me, void *data);

/* Getting */
bk_err forward_list_get_first(void *data, forward_list me);
bk_err forward_list_get_at(void *data, forward_list me, size_t index);
bk_err forward_list_get_last(void *data, forward_list me);

/* Ending */
void forward_list_clear(forward_list me);
forward_list forward_list_destroy(forward_list me);

#endif /* BKTHOMPS_CONTAINERS_FORWARD_LIST_H */


#ifndef BKTHOMPS_CONTAINERS_LIST_H
#define BKTHOMPS_CONTAINERS_LIST_H

/**
 * The list data structure, which is a doubly-linked list.
 */
typedef struct internal_list *list;

/* Starting */
list list_init(size_t data_size);

/* Utility */
size_t list_size(list me);
bk_bool list_is_empty(list me);
void list_copy_to_array(void *arr, list me);
bk_err list_add_all(list me, void *arr, size_t size);

/* Adding */
bk_err list_add_first(list me, void *data);
bk_err list_add_at(list me, size_t index, void *data);
bk_err list_add_last(list me, void *data);

/* Removing */
bk_err list_remove_first(list me);
bk_err list_remove_at(list me, size_t index);
bk_err list_remove_last(list me);

/* Setting */
bk_err list_set_first(list me, void *data);
bk_err list_set_at(list me, size_t index, void *data);
bk_err list_set_last(list me, void *data);

/* Getting */
bk_err list_get_first(void *data, list me);
bk_err list_get_at(void *data, list me, size_t index);
bk_err list_get_last(void *data, list me);

/* Ending */
void list_clear(list me);
list list_destroy(list me);

#endif /* BKTHOMPS_CONTAINERS_LIST_H */


#ifndef BKTHOMPS_CONTAINERS_MAP_H
#define BKTHOMPS_CONTAINERS_MAP_H

/**
 * The map data structure, which is a collection of key-value pairs, sorted by
 * keys, keys are unique.
 */
typedef struct internal_map *map;

/* Starting */
map map_init(size_t key_size, size_t value_size,
             int (*comparator)(const void *const one, const void *const two));

/* Capacity */
size_t map_size(map me);
bk_bool map_is_empty(map me);

/* Accessing */
bk_err map_put(map me, void *key, void *value);
bk_bool map_get(void *value, map me, void *key);
bk_bool map_contains(map me, void *key);
bk_bool map_remove(map me, void *key);

/* Retrieval */
void *map_first(map me);
void *map_last(map me);
void *map_lower(map me, void *key);
void *map_higher(map me, void *key);
void *map_floor(map me, void *key);
void *map_ceiling(map me, void *key);

/* Ending */
void map_clear(map me);
map map_destroy(map me);

#endif /* BKTHOMPS_CONTAINERS_MAP_H */


#ifndef BKTHOMPS_CONTAINERS_MULTIMAP_H
#define BKTHOMPS_CONTAINERS_MULTIMAP_H

/**
 * The multimap data structure, which is a collection of key-value pairs, sorted
 * by keys.
 */
typedef struct internal_multimap *multimap;

/* Starting */
multimap multimap_init(size_t key_size, size_t value_size,
                       int (*key_comparator)(const void *const one,
                                             const void *const two),
                       int (*value_comparator)(const void *const one,
                                               const void *const two));

/* Capacity */
size_t multimap_size(multimap me);
bk_bool multimap_is_empty(multimap me);

/* Accessing */
bk_err multimap_put(multimap me, void *key, void *value);
void multimap_get_start(multimap me, void *key);
bk_bool multimap_get_next(void *value, multimap me);
size_t multimap_count(multimap me, void *key);
bk_bool multimap_contains(multimap me, void *key);
bk_bool multimap_remove(multimap me, void *key, void *value);
bk_bool multimap_remove_all(multimap me, void *key);

/* Retrieval */
void *multimap_first(multimap me);
void *multimap_last(multimap me);
void *multimap_lower(multimap me, void *key);
void *multimap_higher(multimap me, void *key);
void *multimap_floor(multimap me, void *key);
void *multimap_ceiling(multimap me, void *key);

/* Ending */
void multimap_clear(multimap me);
multimap multimap_destroy(multimap me);

#endif /* BKTHOMPS_CONTAINERS_MULTIMAP_H */


#ifndef BKTHOMPS_CONTAINERS_MULTISET_H
#define BKTHOMPS_CONTAINERS_MULTISET_H

/**
 * The multiset data structure, which is a collection of key-value pairs, sorted
 * by keys, keys are unique
 */
typedef struct internal_multiset *multiset;

/* Starting */
multiset multiset_init(size_t key_size,
                       int (*comparator)(const void *const one,
                                         const void *const two));

/* Capacity */
size_t multiset_size(multiset me);
bk_bool multiset_is_empty(multiset me);

/* Accessing */
bk_err multiset_put(multiset me, void *key);
size_t multiset_count(multiset me, void *key);
bk_bool multiset_contains(multiset me, void *key);
bk_bool multiset_remove(multiset me, void *key);
bk_bool multiset_remove_all(multiset me, void *key);

/* Retrieval */
void *multiset_first(multiset me);
void *multiset_last(multiset me);
void *multiset_lower(multiset me, void *key);
void *multiset_higher(multiset me, void *key);
void *multiset_floor(multiset me, void *key);
void *multiset_ceiling(multiset me, void *key);

/* Ending */
void multiset_clear(multiset me);
multiset multiset_destroy(multiset me);

#endif /* BKTHOMPS_CONTAINERS_MULTISET_H */


#ifndef BKTHOMPS_CONTAINERS_PRIORITY_QUEUE_H
#define BKTHOMPS_CONTAINERS_PRIORITY_QUEUE_H

/**
 * The priority_queue data structure, which adapts a container to provide a
 * priority queue. Adapts the vector container.
 */
typedef struct internal_priority_queue *priority_queue;

/* Starting */
priority_queue priority_queue_init(size_t data_size,
                                   int (*comparator)(const void *const one,
                                                     const void *const two));

/* Utility */
size_t priority_queue_size(priority_queue me);
bk_bool priority_queue_is_empty(priority_queue me);

/* Adding */
bk_err priority_queue_push(priority_queue me, void *data);

/* Removing */
bk_bool priority_queue_pop(void *data, priority_queue me);

/* Getting */
bk_bool priority_queue_front(void *data, priority_queue me);

/* Ending */
bk_err priority_queue_clear(priority_queue me);
priority_queue priority_queue_destroy(priority_queue me);

#endif /* BKTHOMPS_CONTAINERS_PRIORITY_QUEUE_H */


#ifndef BKTHOMPS_CONTAINERS_QUEUE_H
#define BKTHOMPS_CONTAINERS_QUEUE_H

/**
 * The queue data structure, which adapts a container to provide a queue
 * (first-in first-out). Adapts the deque container.
 */
typedef struct internal_deque *queue;

/* Starting */
queue queue_init(size_t data_size);

/* Utility */
size_t queue_size(queue me);
bk_bool queue_is_empty(queue me);
bk_err queue_trim(queue me);
void queue_copy_to_array(void *arr, queue me);

/* Adding */
bk_err queue_push(queue me, void *data);

/* Removing */
bk_bool queue_pop(void *data, queue me);

/* Getting */
bk_bool queue_front(void *data, queue me);
bk_bool queue_back(void *data, queue me);

/* Ending */
bk_err queue_clear(queue me);
queue queue_destroy(queue me);

#endif /* BKTHOMPS_CONTAINERS_QUEUE_H */


#ifndef BKTHOMPS_CONTAINERS_SET_H
#define BKTHOMPS_CONTAINERS_SET_H

/**
 * The set data structure, which is a collection of unique keys, sorted by keys.
 */
typedef struct internal_set *set;

/* Starting */
set set_init(size_t key_size,
             int (*comparator)(const void *const one, const void *const two));

/* Capacity */
size_t set_size(set me);
bk_bool set_is_empty(set me);

/* Accessing */
bk_err set_put(set me, void *key);
bk_bool set_contains(set me, void *key);
bk_bool set_remove(set me, void *key);

/* Retrieval */
void *set_first(set me);
void *set_last(set me);
void *set_lower(set me, void *key);
void *set_higher(set me, void *key);
void *set_floor(set me, void *key);
void *set_ceiling(set me, void *key);

/* Ending */
void set_clear(set me);
set set_destroy(set me);

#endif /* BKTHOMPS_CONTAINERS_SET_H */


#ifndef BKTHOMPS_CONTAINERS_STACK_H
#define BKTHOMPS_CONTAINERS_STACK_H

/**
 * The stack data structure, which adapts a container to provide a stack
 * (last-in first-out). Adapts the deque container.
 */
typedef struct internal_deque *stack;

/* Starting */
stack stack_init(size_t data_size);

/* Utility */
size_t stack_size(stack me);
bk_bool stack_is_empty(stack me);
bk_err stack_trim(stack me);
void stack_copy_to_array(void *arr, stack me);

/* Adding */
bk_err stack_push(stack me, void *data);

/* Removing */
bk_bool stack_pop(void *data, stack me);

/* Getting */
bk_bool stack_top(void *data, stack me);

/* Ending */
bk_err stack_clear(stack me);
stack stack_destroy(stack me);

#endif /* BKTHOMPS_CONTAINERS_STACK_H */


#ifndef BKTHOMPS_CONTAINERS_UNORDERED_MAP_H
#define BKTHOMPS_CONTAINERS_UNORDERED_MAP_H

/**
 * The unordered_map data structure, which is a collection of key-value pairs,
 * hashed by keys, keys are unique
 */
typedef struct internal_unordered_map *unordered_map;

/* Starting */
unordered_map unordered_map_init(size_t key_size,
                                 size_t value_size,
                                 unsigned long (*hash)(const void *const key),
                                 int (*comparator)(const void *const one,
                                                   const void *const two));

/* Utility */
bk_err unordered_map_rehash(unordered_map me);
size_t unordered_map_size(unordered_map me);
bk_bool unordered_map_is_empty(unordered_map me);

/* Accessing */
bk_err unordered_map_put(unordered_map me, void *key, void *value);
bk_bool unordered_map_get(void *value, unordered_map me, void *key);
bk_bool unordered_map_contains(unordered_map me, void *key);
bk_bool unordered_map_remove(unordered_map me, void *key);

/* Ending */
bk_err unordered_map_clear(unordered_map me);
unordered_map unordered_map_destroy(unordered_map me);

#endif /* BKTHOMPS_CONTAINERS_UNORDERED_MAP_H */


#ifndef BKTHOMPS_CONTAINERS_UNORDERED_MULTIMAP_H
#define BKTHOMPS_CONTAINERS_UNORDERED_MULTIMAP_H

/**
 * The unordered_multimap data structure, which is a collection of key-value
 * pairs, hashed by keys.
 */
typedef struct internal_unordered_multimap *unordered_multimap;

/* Starting */
unordered_multimap
unordered_multimap_init(size_t key_size,
                        size_t value_size,
                        unsigned long (*hash)(const void *const key),
                        int (*key_comparator)(const void *const one,
                                              const void *const two),
                        int (*value_comparator)(const void *const one,
                                                const void *const two));

/* Utility */
bk_err unordered_multimap_rehash(unordered_multimap me);
size_t unordered_multimap_size(unordered_multimap me);
bk_bool unordered_multimap_is_empty(unordered_multimap me);

/* Accessing */
bk_err unordered_multimap_put(unordered_multimap me, void *key, void *value);
void unordered_multimap_get_start(unordered_multimap me, void *key);
bk_bool unordered_multimap_get_next(void *value, unordered_multimap me);
size_t unordered_multimap_count(unordered_multimap me, void *key);
bk_bool unordered_multimap_contains(unordered_multimap me, void *key);
bk_bool unordered_multimap_remove(unordered_multimap me,
                                  void *key, void *value);
bk_bool unordered_multimap_remove_all(unordered_multimap me, void *key);

/* Ending */
bk_err unordered_multimap_clear(unordered_multimap me);
unordered_multimap unordered_multimap_destroy(unordered_multimap me);

#endif /* BKTHOMPS_CONTAINERS_UNORDERED_MULTIMAP_H */


#ifndef BKTHOMPS_CONTAINERS_UNORDERED_MULTISET_H
#define BKTHOMPS_CONTAINERS_UNORDERED_MULTISET_H

/**
 * The unordered_multiset data structure, which is a collection of keys, hashed
 * by keys.
 */
typedef struct internal_unordered_multiset *unordered_multiset;

/* Starting */
unordered_multiset
unordered_multiset_init(size_t key_size,
                        unsigned long (*hash)(const void *const key),
                        int (*comparator)(const void *const one,
                                          const void *const two));

/* Utility */
bk_err unordered_multiset_rehash(unordered_multiset me);
size_t unordered_multiset_size(unordered_multiset me);
bk_bool unordered_multiset_is_empty(unordered_multiset me);

/* Accessing */
bk_err unordered_multiset_put(unordered_multiset me, void *key);
size_t unordered_multiset_count(unordered_multiset me, void *key);
bk_bool unordered_multiset_contains(unordered_multiset me, void *key);
bk_bool unordered_multiset_remove(unordered_multiset me, void *key);
bk_bool unordered_multiset_remove_all(unordered_multiset me, void *key);

/* Ending */
bk_err unordered_multiset_clear(unordered_multiset me);
unordered_multiset unordered_multiset_destroy(unordered_multiset me);

#endif /* BKTHOMPS_CONTAINERS_UNORDERED_MULTISET_H */


#ifndef BKTHOMPS_CONTAINERS_UNORDERED_SET_H
#define BKTHOMPS_CONTAINERS_UNORDERED_SET_H

/**
 * The unordered_set data structure, which is a collection of unique keys,
 * hashed by keys.
 */
typedef struct internal_unordered_set *unordered_set;

/* Starting */
unordered_set unordered_set_init(size_t key_size,
                                 unsigned long (*hash)(const void *const key),
                                 int (*comparator)(const void *const one,
                                                   const void *const two));

/* Utility */
bk_err unordered_set_rehash(unordered_set me);
size_t unordered_set_size(unordered_set me);
bk_bool unordered_set_is_empty(unordered_set me);

/* Accessing */
bk_err unordered_set_put(unordered_set me, void *key);
bk_bool unordered_set_contains(unordered_set me, void *key);
bk_bool unordered_set_remove(unordered_set me, void *key);

/* Ending */
bk_err unordered_set_clear(unordered_set me);
unordered_set unordered_set_destroy(unordered_set me);

#endif /* BKTHOMPS_CONTAINERS_UNORDERED_SET_H */


#ifndef BKTHOMPS_CONTAINERS_VECTOR_H
#define BKTHOMPS_CONTAINERS_VECTOR_H

/**
 * The vector data structure, which is a dynamic contiguous array.
 */
typedef struct internal_vector *vector;

/* Starting */
vector vector_init(size_t data_size);

/* Utility */
size_t vector_size(vector me);
size_t vector_capacity(vector me);
bk_bool vector_is_empty(vector me);
bk_err vector_reserve(vector me, size_t size);
bk_err vector_trim(vector me);
void vector_copy_to_array(void *arr, vector me);
void *vector_get_data(vector me);
bk_err vector_add_all(vector me, void *arr, size_t size);

/* Adding */
bk_err vector_add_first(vector me, void *data);
bk_err vector_add_at(vector me, size_t index, void *data);
bk_err vector_add_last(vector me, void *data);

/* Removing */
bk_err vector_remove_first(vector me);
bk_err vector_remove_at(vector me, size_t index);
bk_err vector_remove_last(vector me);

/* Setting */
bk_err vector_set_first(vector me, void *data);
bk_err vector_set_at(vector me, size_t index, void *data);
bk_err vector_set_last(vector me, void *data);

/* Getting */
bk_err vector_get_first(void *data, vector me);
bk_err vector_get_at(void *data, vector me, size_t index);
bk_err vector_get_last(void *data, vector me);

/* Ending */
bk_err vector_clear(vector me);
vector vector_destroy(vector me);

#endif /* BKTHOMPS_CONTAINERS_VECTOR_H */
