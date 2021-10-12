// Compile with:
// gcc tlsh-test.c -lmvptree -ltlsh -lstdc++ -L. -o tlsh-test

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "tlsh-wrapper.h"
#include "mvptree.h"

#define MVP_BRANCHFACTOR 2
#define MVP_PATHLENGTH   5
#define MVP_LEAFCAP     25


// Fast tanimoto code with 8 bit LUT
// by Ernst-Georg Schmid
// https://github.com/ergo70/tanimoto

static const uint8_t popcount_counts_byte[] =
{
    0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8
};

float tanimoto_distance(MVPDP *pointA, MVPDP *pointB){

    if (!pointA || !pointB || pointA->datalen != pointB->datalen) return -1.0f;

    uint8_t * data1 = pointA->data;
    uint8_t * data2 = pointB->data;

    unsigned int and_count=0, or_count=0;
    int size = pointA->datalen;
    uint8_t tmp;
    float result;

    while (size--)
    {
        tmp = (*data2 | *data1);
        or_count += popcount_counts_byte[tmp];

        tmp = (*data2 & *data1);
        and_count += popcount_counts_byte[tmp];

        data2++;
        data1++;
    }

    result = (float) 1.0f - and_count / (or_count * 1.0f);

    /*
    printf("\nComparing: %s\n", (char*) pointA->data);
    printf("To       : %s\n", (char*) pointB->data);
    printf("Distance : %f\n", result);
    */

    return result;
}



int main () {

    int showvers = 0;


    const char * mvp_file = "tree.mvp";

    MVPError err;
    MVPTree* tree;
    CmpFunc distance_func = tanimoto_distance;


    printf("Reading MVP Tree from file (%s)...\n", mvp_file);
    tree = mvptree_read(mvp_file, distance_func, MVP_BRANCHFACTOR, MVP_PATHLENGTH, MVP_LEAFCAP, &err);

    if(err != MVP_SUCCESS || tree == NULL) {

        printf("Unable to read MVP Tree from file, initializing new one...\n");

        Tlsh* t[10];

        for(int i=0; i<10; i++) {
            t[i] = Tlsh_new();
        }

        const char *str[10];
        str[0] = "This is a test for Lili Diao. This is a string. Hello Hello Hello ";
        str[1] = "This is a test for Jon Oliver. This is a string. Hello Hello Hello ";
        str[2] = "This is a test for Lili Ciao. This is a string. Hello Hello Hello ";
        str[3] = "This is a test for Lili Diao.";
        str[4] = "This is a string. Hello Hello Hello ";
        str[5] = "Hello Hello Hello ";
        str[6] = " ";
        str[7] = "a test is a string.";
        str[8] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        str[9] = "a test for Lili Dao. Hello Hello";

        for(int i=0; i<10; i++) {

            char minSizeBuffer[512];
            for (int i = 0; i < 511; i++) {
                minSizeBuffer[i] = i % 26 + 'A';
            }

            minSizeBuffer[511] = 0;
            strncpy(minSizeBuffer, str[i], strlen(str[i]));
            Tlsh_final(t[i], (const unsigned char*) minSizeBuffer, 512, 0);

            printf("String %d: %s\n", i, str[i]);
        }


        tree = mvptree_alloc(NULL, distance_func,  MVP_BRANCHFACTOR, MVP_PATHLENGTH, MVP_LEAFCAP);


        for(int i=0; i<10; i++) {

            MVPDP *newpnt = dp_alloc(BYTEARRAY);

            newpnt->data = strdup(Tlsh_get_hash(t[i], showvers));
            newpnt->datalen = strlen(newpnt->data);

            printf("Adding new point %d: %s (size = %d)\n", i, (char*)newpnt->data, newpnt->datalen);

            char scratch[32];
            snprintf(scratch, 32, "point%d", i);
            newpnt->id = strdup(scratch);


            err = mvptree_add(tree, &newpnt, 1);

            if(err != MVP_SUCCESS) {
                printf("MVPError: %d\n", err);
                exit(1);
            }
        }

        for(int i=0; i<10; i++) {
            Tlsh_delete(t[i]);
        }


        printf("Writing MVP Tree to file (%s)...\n", mvp_file);
        err = mvptree_write(tree, mvp_file, 00755);
    }


    printf("Querying MVP Tree\n");

    const char * query = "";
    //const char * query = "This is a test for Lili Diao. This is a string. Hello Hello Hello ";
    //const char * query = "This is a test for Lili Biao. This is a string. Hello Hello Hello ";
    //const char * query = "This is a string. Hello Hello Hello ";
    Tlsh * t_query = Tlsh_new();
    char minSizeBuffer[512];
    for (int i = 0; i < 511; i++) {
        minSizeBuffer[i] = i % 26 + 'A';
    }

    minSizeBuffer[511] = 0;
    strncpy(minSizeBuffer, query, strlen(query));
    Tlsh_final(t_query, (const unsigned char*) minSizeBuffer, 512, 0);

    MVPDP *query_node = dp_alloc(BYTEARRAY);
    query_node->data = strdup(Tlsh_get_hash(t_query, showvers));
    query_node->datalen = strlen(query_node->data);
    query_node->id = strdup("Query node");

    printf("Query string: %s\n", query);
    printf("Query point: %s (size = %d)\n", (char*)query_node->data, query_node->datalen);

    unsigned int knearest = 1;
    unsigned int nbresults = 0;
    float radius = 0.1;
    MVPDP **results = mvptree_retrieve(tree, query_node, knearest, radius, &nbresults, &err);

    /*if(err != MVP_SUCCESS) {
        printf("MVPError: %d\n", err);
        exit(1);
    }*/


    printf("Retrieval results: %d\n", nbresults);

    for(int i=0; i < nbresults; i++) {
        printf("NODE FOUND: %s (id=%s, distance=%f)\n", (char *)results[i]->data, results[i]->id, tanimoto_distance(results[i], query_node) );
    }

    free(results);


    dp_free(query_node, free);
    mvptree_clear(tree, free);
    free(tree);

    Tlsh_delete(t_query);

}

