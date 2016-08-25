#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>

#include <config.h>
#include <debug.h>
#include <param.h>
#include <deftype.h>
/**buf = dir+"/"+fname
 * buf len must be MAX_FILE_NAME_LEN
 */
void check_build_path(const char *dir, const char *fname, char *fbuf)
{
    CHECK2(dir != NULL && fname != NULL);
    CHECK2(strlen(dir) + strlen(fname) + 1 < MAX_FILE_NAME_LEN);
    strcpy(fbuf, dir);
    strcat(fbuf, "/");
    strcat(fbuf, fname);

}

void save_aparam(pbc_param_t par, char *dir)
{
    char fbuf[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;

    check_build_path(dir, APARAM, fbuf);
    DEBUG("File:%s\n", fbuf);
    CHECK2(fp = fopen(fbuf, "w"));
    pbc_param_out_str(fp, par);
    fclose(fp);
}

void save_int(int n, char *dir, char *name)
{
    char fbuf[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;

    check_build_path(dir, name, fbuf);
    CHECK2(fp = fopen(fbuf, "w"));
    fprintf(fp, "%d\n", n);
    fclose(fp);
}

void make_dir(char *src, int n)
{
    char dir[MAX_FILE_NAME_LEN];

    CHECK(access(src, W_OK));
    snprintf(dir, MAX_FILE_NAME_LEN, "/%d/", n);
    CHECK2(strlen(src) + strlen(dir) < MAX_FILE_NAME_LEN);
    strcat(src, dir);
    if(access(src, W_OK))
        CHECK(mkdir(src, 0666));

}

void write_to_fp(FILE *fp, const char *buf, int len, uint64 pos)
{
    CHECK(fseek(fp, pos, SEEK_SET));
    CHECK2(fwrite(buf, len, 1, fp) == 1);
}

void save_ele(element_t g, const char *fname)
{

    int n = element_length_in_bytes(g);
    int ret;
    FILE *fp = NULL;
    char buf[ELEMENT_MAX_LEN];
    CHECK2(n<=ELEMENT_MAX_LEN);
    CHECK2(element_to_bytes(buf, g) == n);
    CHECK2(fp = fopen(fname,"wb"));
    write_to_fp(fp, buf, n, 0);
    fclose(fp);
}
