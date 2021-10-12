#ifndef WRAPPER_H_
#define WRAPPER_H_

/* From:
 * https://stackoverflow.com/questions/31903005/how-to-mix-c-and-c-correctly
 */

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct Tlsh Tlsh;

    Tlsh* Tlsh_new();
    const char* Tlsh_get_hash_buffer(Tlsh* tlsh, char *buffer, unsigned int bufSize, int showvers);
    const char* Tlsh_get_hash(Tlsh* tlsh, int showvers);
    void Tlsh_update(Tlsh* tlsh, const unsigned char* data, unsigned int len);
    void Tlsh_final(Tlsh* tlsh, const unsigned char* data, unsigned int len, int fc_cons_option);
    int Tlsh_from_str(Tlsh* tlsh, const char* str);
    int Tlsh_total_diff(Tlsh* tlsh, const Tlsh *other, int len_diff);
    void Tlsh_reset(Tlsh* tlsh);
    void Tlsh_delete(Tlsh* tlsh);

#ifdef __cplusplus
}
#endif
#endif /* WRAPPER_H_ */
