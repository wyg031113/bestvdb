#ifndef __PARAM_H__
#define __PARAM_H__

#include <deftype.h>

#define MAX_FILE_NAME_LEN 128
#define DEF_Q 512
#define DEF_R 160
#define DEF_N 100
#define APARAM "a.param"
#define FILE_N "n"
#define FILE_HI "hi"
#define FILE_HIJ "hij"
#define FILE_Y "Y"
#define FILE_y "y"
#define FILE_g "g"
#define ELEMENT_MAX_LEN 256
int check_build_path(const char *dir, const char *fname, char *fbuf);
void save_aparam(pbc_param_t par, char *dir);
void save_int(int n, char *dir, char *name);
void make_dir(char *src, int n);
void save_ele(element_t g, const char *fname);
void write_to_fp(FILE *fp, const char *buf, int len, uint64 pos);
#endif /*__PARAM_H__*/
