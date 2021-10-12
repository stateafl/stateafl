/*
 *  MVPTree c library
 *  Copyright (C) 2008-2009 by D. Grant Starkweather.
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  D Grant Starkweather - starkd88@gmail.com
 */

#ifndef _MVPTREE_H
#define _MVPTREE_H

/*data type for a datapoint - refers to the bitwidth of each element */
typedef enum mvp_datatype_t { 
    BYTEARRAY = 1, 
    UINT16ARRAY = 2, 
    UINT32ARRAY = 4, 
    UINT64ARRAY = 8 
} MVPDataType;

typedef enum nodetype_t { 
    INTERNAL_NODE = 1, 
    LEAF_NODE 
} NodeType;

/* error codes */
typedef enum mvp_error_t {
    MVP_SUCCESS,            /* no error */
    MVP_ARGERR,             /* argument error */
    MVP_NODISTANCEFUNC,     /* no distance function found */
    MVP_MEMALLOC,           /* mem alloc error */
    MVP_NOLEAF,             /* could not alloc leaf node */
    MVP_NOINTERNAL,         /* could not alloc internal node */
    MVP_PATHALLOC,          /* path alloc error */
    MVP_VPNOSELECT,         /* could not select vantage points */
    MVP_NOSV1RANGE,         /* could not calculate range of points from sv1 */
    MVP_NOSV2RANGE,         /* could not calculate range of points from sv2 */
    MVP_NOSPACE,            /* points too close to one another, too compact */
    MVP_NOSORT,             /* unable to sort points */
    MVP_FILEOPEN,           /* trouble opening file */
    MVP_FILECLOSE,          /* trouble closing file */
    MVP_MEMMAP,             /* mem map trouble */
    MVP_MUNMAP,             /* mem unmap trouble */
    MVP_NOWRITE,            /* could not write to file */
    MVP_FILETRUNCATE,       /* could not extend file */
    MVP_MREMAPFAIL,         /* unable to map/unmap file */
    MVP_TYPEMISMATCH,       /* trying to add datapoints of one datatype */
                            /* to tree that already contains another type */
    MVP_KNEARESTCAP,        /* number results found reaches knearest limit */
    MVP_EMPTYTREE,
    MVP_NOSPLITS,           /* unable to calculate split points */
    MVP_BADDISTVAL,         /* val from distance function either NaN or less than 0 */
    MVP_FILENOTFOUND,       /* file not found */
    MVP_UNRECOGNIZED,       /* unrecognized node */
} MVPError;

typedef struct mvp_datapoint_t {
    char *id;               /* null-terminated id string */
    void *data;             /* data for this data point */
    float *path;            /* path of distances of data point from all vantage points down tree*/
    unsigned int datalen;   /* length of data in the type designated */    
    MVPDataType type;       /* type of data (the bitwidth of each data element) */
} MVPDP;

/* call back function for mvp tree functions - to performa distance calc.'s*/
typedef float (*CmpFunc)(MVPDP *pointA, MVPDP *pointB);

/* Callback function to pass to mvp_clear() to free id and data members of the datapoints, */
/* since the id and data arrays are allocated by user, not by dp_alloc() function. */
typedef void (*MVPFreeFunc)(void *ptr);

typedef struct node_internal_t {
    NodeType type;
    MVPDP *sv1, *sv2;
    float *M1, *M2;
    void **child_nodes;
} InternalNode;

typedef struct node_leaf_t {
    NodeType type;
    MVPDP *sv1, *sv2;
    MVPDP **points;
    float *d1, *d2;
    unsigned int nbpoints;
} LeafNode;
   

typedef union node_t {
    LeafNode leaf;
    InternalNode internal;
} Node;


typedef struct mvptree_t {
    int branchfactor;      /* branch factor of tree, e.g. 2                           */
    int pathlength;        /* number distances stored for a datapoint's distance      */
                           /* from each vantage point going down the tree.            */
                           /* Refers to the array of float's stored in each datapoint.*/
    int leafcap;           /* capacity of leaf nodes  (number datapoints)             */
    int fd;                /* internal use                                            */
    int k;                 /* internal use for retrieve function (knearest)           */
    MVPDataType datatype;  /* internal use                                            */  
    off_t pos;             /* internal use for mvp_read() and mvp_write()             */
    off_t size;            /* internal use for mvp_read() and mvp_write()             */
    off_t pgsize;          /* system page size (interal use)                          */
    char *buf;             /* internal use                                            */
    Node *node;            /* reference to top of tree                                */
    CmpFunc dist;          /* distance function - e.g. L1 or L2                       */
} MVPTree;


/*   DP* dp_alloc
 *
 *   DESCRIPTION:
 *
 *   allocate a datapoint on the heap
 *
 *   ARGUMENTS:
 *
 *   type - DataType value to indicate the type of data the datapoint represents.
 *
 *   RETURN:
 *   
 *   pointer to DP structure, NULL for error.    
 *
 */
MVPDP* dp_alloc(MVPDataType type);

/*   dp_free
 *
 *   DESCRIPTION:
 *
 *   free a datapoint
 *
 *   ARGUMENTS:
 *
 *   dp - pointer to datapoint to be free'd.
 *
 *   free_func - callback function that will be used to free the id and data parts of a DP 
 *
 *   RETURN: 
 *
 *   void
 */
void dp_free(MVPDP *dp, MVPFreeFunc free_func);

/*   mvptree_alloc
 * 
 *   DESCRIPTION:
 *
 *   ARGUMENTS:
 *
 *   tree - ptr to MVPTree to initialize (NULL to allocate one on the heap 
 *
 *   distance - callback function (the distance function to use in the mvp tree
 *   
 *    bf - int value for the tree branch factor - e.g. 2
 *
 *    p  - int value for the path length to use for each data point
 *
 *    k  - int value for leaf capacity of each leaf node - maximum number of datapoints 
 *
 *   RETURN:
 *
 *   MVPTree* ptr, NULL for error
 *    
 */
MVPTree* mvptree_alloc(MVPTree *tree,CmpFunc distance,
                                       unsigned int bf,unsigned int p,unsigned int k);

/*
 *  mvptree_clear
 *  
 *  DESCRIPTION:
 *
 *  Clear out the tree. All the datapoints that have been added to the tree
 *  are also free'd with dp_free(). You can specify a free function to free
 *  the portions of the DP struct which are user allocated (e.g. the id and 
 *  data fields).
 *
 *  ARGUMENTS:
 *
 *  tree - ptr to tree to clear out
 *
 *  free_func - ptr to function to free the datapoint's id and data fields
 *
 *  RETURN 
 *
 *  void
 */
void mvptree_clear(MVPTree *tree, MVPFreeFunc free_func);

/*
 *   mvptree_add
 *
 *   DESCRIPTION:
 *
 *   Add a list of datapoints to a tree. Note: the datapoints are subsequently
 *   owned by the tree, and a call to mvptree_clear() will invoke dp_free() on
 *   all its datapoints. (See mvptree_clear()). However, it does not own the array
 *   containing the pointers to the datapoints.  This must still be free'd by the user.
 *
 *   ARGUMENTS:
 *
 *   tree - ptr to MVPTree a previously allocated tree.
 *
 *   points - array of DP ptrs to add to the tree
 *
 *   nbpoints - unsigned int for the number of datapoint ptrs in points array
 *
 *   RETURN 
 *
 *   MVPError error code
 */
MVPError mvptree_add(MVPTree *tree, MVPDP **points, unsigned int nbpoints);

/*
 *   mvptree_retrieve
 *  
 *   DESCRIPTION:
 *   
 *   retrieve knearest neighbors from the tree
 *
 *   ARGUMENTS:
 *
 *   tree - ptr to the MVPTree
 *
 *   target - target datapoint
 *
 *   knearest - maximum number of datapoints to return
 *
 *   radius   -  distance from the target to include in returned list.
 *
 *   nbresults - ptr to int to contain the number of results returned to user.
 *
 *   error - ptr to error value to return error to user
 *
 *   RETURN:
 *
 *   MVPDP** array of ptrs to datapoints. (The user must free the array, but not the datapoints
 *           They are still owned by the tree.)
 *
 */
MVPDP** mvptree_retrieve(MVPTree *tree, MVPDP *target, unsigned int knearest, float radius,
                                       unsigned int *nbresults, MVPError *error);

/*
 *   mvptree_write
 *
 *   DESCRIPTION:
 *
 *   write out a tree to a file
 *
 *   ARGUMENTS:
 *
 *   tree - ptr to MVPTree struct
 *
 *   filename - null-terminated char array
 *
 *   mode - int value for mode for file open.
 *
 *   RETURN
 *
 *   MVPError code
 *
 */
MVPError mvptree_write(MVPTree *tree, const char *filename, int mode);

/*   mvptree_read
 *
 *   DESCRIPTION:
 *
 *   read a tree from a previously written file into MVPTree struct
 *
 *   ARGUMENTS:
 *
 *   filename - null-terminated char array
 *
 *   fnc - callback function for distance function to use 
 *
 *   error - pointer to MVPError code enum
 *
 *   RETURN
 *
 *   MVPTree ptr, or NULL on error (and error is set to error code)
 *
 */
MVPTree* mvptree_read(const char *filename, CmpFunc fnc, int branchfactor, int pathlength,\
                                                  int leafcapacity, MVPError *error);

/*   mvptree_print
 *
 *   DESCRIPTION:
 *
 *   print out a tree
 *
 *   ARGUMENT:
 *
 *   stream - pointer to FILE stream to which to print.
 *
 *   tree   - ptr to the MVPTree struct to print.
 *
 *   RETURN:
 *
 *   MVPERror code
 *
 */
MVPError mvptree_print(FILE *stream, MVPTree *tree);

/*   mvp_error
 *
 *   DESCRIPTION:
 *
 *   convenience function to return human readable string of error code
 *
 *   ARGUMENTS:
 *
 *   err - MVPError code
 *
 *   RETURN:
 *
 *   string value for error
 *
 */

const char* mvp_errstr(MVPError err);

#endif /* _MVPTREE_H */
