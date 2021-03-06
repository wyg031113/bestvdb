#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <deftype.h>
#include <time.h>
#include <sys/stat.h>

#include <config.h>
#include <debug.h>
#include <param.h>
#define MAX_PROCESS 64
struct Hi_Task
{
    uint64 start;
    uint64 len;
    char *fname;
    pid_t pid;
};

int q = 512;
int r = 160;
int n = 100;
int nproc = 1;
int help = 0;
char server_conf[MAX_FILE_NAME_LEN] = "../server/vdb_server_conf/params";
char client_conf[MAX_FILE_NAME_LEN] = "../client/vdb_client_conf/params";

char pk_sql_ip[17] = "127.0.0.1";
int  pk_sql_port = 3306;
char pk_sql_user[64] = "root";
char pk_sql_passwd[64] = "letmein";
char pk_sql_dbname[64] = "vdb_server";
const char *config_file = "/etc/vdb_paramgen/paramgen.conf";

struct config config_table[]=
{
        {"q", &q, CFG_INT, sizeof(int), "q:", "q in G"},
        {"r", &r, CFG_INT, sizeof(int), "r:", "r in G"},
        {"n", &n, CFG_INT, sizeof(int), "n:", "database size"},
        {"nproc", &nproc, CFG_INT, sizeof(int), "t:", "thread num"},
        {"help", &help, CFG_INT, sizeof(int), "h", "help"},
        {"server_conf", server_conf, CFG_STR, MAX_FILE_NAME_LEN, "s:", "server's config file"},
        {"client_conf", client_conf, CFG_STR, MAX_FILE_NAME_LEN, "c:", "client's config file"},
        {"pk_sql_ip", pk_sql_ip, CFG_STR, 17, "", "" },
        {"pk_sql_port", &pk_sql_port, CFG_INT, sizeof(int), "", ""},
        {"pk_sql_user", pk_sql_user, CFG_STR, 64, "", "" },
        {"pk_sql_passwd", pk_sql_passwd, CFG_STR, 64, "", "" },
        {"pk_sql_dbname", pk_sql_dbname, CFG_STR, 64, "", "" },
        {NULL, NULL, 0, 0, "", NULL}
};

pairing_t pair;
element_t *z;
element_t g;
pbc_param_t par;
//element_t y;
//element_t Y;


void destroy_global_elemment();
void show_all_global_element(void);

void gen_aparam(void)
{
    FILE *fser;
    char fname;
    pbc_param_init_a_gen(par, r, q);
    pairing_init_pbc_param(pair, par);
    save_aparam(par, server_conf);
    //save_aparam(par, client_conf);
    //save_aparam(par, ".");

#ifdef DEBUG_ON
    pbc_param_out_str(stdout, par);
#endif
}

void save_n()
{
    save_int(n, server_conf, FILE_N);
    //save_int(n, client_conf, FILE_N);
}

void buid_config_dir(void)
{
    make_dir(server_conf, n);
    //make_dir(client_conf, n);
    DEBUG("Server config dir:%s\n", server_conf);
    //DEBUG("Client config dir:%s\n", client_conf);
}

void *hi_process(void *arg)
{
    struct Hi_Task *ht;
    FILE *fp = NULL;
	element_pp_t gpp;
    element_t hi;
    uint64 i;
    char ele[ELEMENT_MAX_LEN];
    int ele_len;

    CHECK2(ht = (struct Hi_Task *) arg);
    DEBUG("MyHITask->start:%lld len:%lld file:%s pid = %d\n", ht->start, ht->len, ht->fname, getpid());
    CHECK2(fp = fopen(ht->fname, "wb"));

    element_init_G1(hi, pair);
	element_pp_init(gpp, g);
    ele_len = pairing_length_in_bytes_compressed_G1(pair);
    CHECK(fseek(fp, ht->start * ele_len, SEEK_SET));
    for(i = 0; i < ht->len; i++)
    {
		element_pp_pow_zn(hi, z[i+ht->start], gpp);
        CHECK2(element_to_bytes_compressed(ele, hi) == ele_len);
        CHECK2(fwrite(ele, ele_len, 1, fp) == 1);
    }
    element_clear(hi);
	element_pp_clear(gpp);
    fclose(fp);
    return 0;
}
void *hij_process(void*arg)
{
    struct Hi_Task *ht;
    FILE *fp = NULL;
	element_pp_t gpp;
    element_t hij;
    element_t mulz;

    uint64 i;
    uint64 j;
    uint64 nele = 0;
    char ele[ELEMENT_MAX_LEN];
    int ele_len;

    //element_set(gx, g);
    CHECK2(ht = (struct Hi_Task *) arg);
    CHECK2(fp = fopen(ht->fname, "wb"));

    element_init_G1(hij, pair);
    element_init_Zr(mulz, pair);
	element_pp_init(gpp, g);
    ele_len = pairing_length_in_bytes_compressed_G1(pair);
    DEBUG("MyHIJTask->start:%lld len:%lld file:%s each_hij_len=%d pid=%d\n", ht->start, ht->len, ht->fname, ele_len, getpid());
    CHECK(fseek(fp, (ht->start * (ht->start-1))/2*ele_len, SEEK_SET));
    for(i = ht->start; i < ht->start + ht->len; i++)
        for(j = 0; j < i; j++)
        {
		    element_mul_zn(mulz, z[i],z[j]);
		    element_pp_pow_zn(hij, mulz, gpp);
            CHECK2(element_to_bytes_compressed(ele, hij) == ele_len);
            CHECK2(fwrite(ele, ele_len, 1, fp) == 1);
        }

    int new_start = n - ht->start - ht->len;
    if(new_start == n/2 && n%2 == 1)
        new_start++;
    CHECK(fseek(fp, (new_start * (new_start-1))/2*ele_len, SEEK_SET));
    for(i = new_start; i < n - ht->start; i++)
        for(j = 0; j < i; j++)
        {
		    element_mul_zn(mulz, z[i],z[j]);
		    element_pp_pow_zn(hij, mulz, gpp);
            CHECK2(element_to_bytes_compressed(ele, hij) == ele_len);
            CHECK2(fwrite(ele, ele_len, 1, fp) == 1);
        }

	element_pp_clear(gpp);
    fclose(fp);
    return 0;

}

void task_split(int n, int nproc, void *(*thread)(void *arg), const char *file_name)
{
    int i;
    struct Hi_Task *hi_tasks = NULL;
    char fbuf[MAX_FILE_NAME_LEN];
    uint64 task_len = 0;
    check_build_path(server_conf, file_name, fbuf);
    task_len = (n / nproc) + ( (n % nproc) == 0? 0 : 1);
    nproc = n/task_len + ((n%task_len)==0?0:1);
    CHECK2(hi_tasks = malloc(sizeof(struct Hi_Task) * nproc));
    for(i = 0; i < nproc; i++)
    {
        hi_tasks[i].fname = fbuf;
        hi_tasks[i].start = i * task_len;
        if(i == nproc - 1)
            hi_tasks[i].len = n - task_len * i;
        else
            hi_tasks[i].len = task_len;
        //CHECK(pthread_create(&hi_tasks[i].tid, NULL, thread, &hi_tasks[i]));
    }
    if(nproc == 1)
    {
            DEBUG("Process %d begin...\n", i);
            thread(&hi_tasks[0]);
            DEBUG("Process %d finish...\n", i);
    }
    else
    for(i = 0; i < nproc; i++)
    {
        if((hi_tasks[i].pid = fork())==0)
        {
            DEBUG("Process %d begin...\n", i);
            thread(&hi_tasks[i]);
            DEBUG("Process %d finish...\n", i);
            exit(0);
        }
    }

    int status = 0;
    for(i = 0; nproc > 1 && i < nproc; i++)
        waitpid(hi_tasks[i].pid, &status, 0);
    printf("Master.....\n");
    free(hi_tasks);
    /*
    for(i = 0; i < nproc; i++)
    {
        int status = 0;
        pthread_join(hi_tasks[i].tid, (void**)&status);
        CHECK2(status == 0);
    }
    */

}

int save_params_to_db()
{
    void *conn_pk;
    char fhi[MAX_FILE_NAME_LEN];
    char fhij[MAX_FILE_NAME_LEN];
    char fpair[MAX_FILE_NAME_LEN];
    FILE *fpairp = NULL;
    char *param_str = NULL;
    int param_len = 0;
    struct stat st;
    int ret;
    CHECK_GO(check_build_path(server_conf, APARAM, fpair) == SUCCESS, out);
    snprintf(fhi, MAX_FILE_NAME_LEN, "%d/%s", n, FILE_HI);
    snprintf(fhij, MAX_FILE_NAME_LEN, "%d/%s", n, FILE_HIJ);
    CHECK_GO(0 == stat(fpair, &st), out);
    CHECK_GO(param_str = (char*)malloc(st.st_size+1), out);
    CHECK_GO(fpairp = fopen(fpair, "r"), out);
    CHECK_GO(1 == fread(param_str, st.st_size, 1, fpairp), out);
    param_str[st.st_size] = '\0';
    int nx = element_length_in_bytes_compressed(g);
    CHECK_GO(NULL != (conn_pk = (void*)get_connection(pk_sql_ip, pk_sql_port, pk_sql_user, pk_sql_passwd, pk_sql_dbname)), out);
    CHECK_GO(SUCCESS == insert_pair(conn_pk, param_str, g, n, fhi, fhij), out);
    ret = SUCCESS;
out:
    if(param_str)   free(param_str);
    if(fpairp)      fclose(fpairp);
    if(conn_pk)     release_connection(conn_pk);
    return ret;
}
void gene_vdb_param(void)
{
    int i;
    char fbuf[MAX_FILE_NAME_LEN];
    uint64 start, end;
	CHECK2(z = malloc(sizeof(element_t) * n));

    INFO("Random select g.\n");
	element_init_G1(g, pair);		//let g be a generator of G1
   	element_random(g);
    check_build_path(server_conf, FILE_g, fbuf);
    save_ele(g, fbuf);

    INFO("Random select zi...\n");
	for(i = 0; i < n; i++)
	{
        element_init_Zr(z[i], pair);			//let z in ZZr
		element_random(z[i]);
	}
    start = time(NULL);
    task_split(n, nproc, hi_process, FILE_HI);
    end = time(NULL);
    INFO("%d threads to calc hi, use %.2f seconds\n", nproc, (double)(end-start));

#ifdef DEBUG_ON
    start = time(NULL);
    task_split(n, 1, hi_process, "Hi_test");
    end = time(NULL);
    INFO("%d threads to calc hi, use %.2f seconds\n", 1, (double)(end-start));
#endif
    start = time(NULL);
    task_split(n/2+(n%2==1?1:0), nproc, hij_process, FILE_HIJ);
    end = time(NULL);
    INFO("%d threads to calc hij, use %.2f seconds\n", nproc, (double)(end-start));
#ifdef DEBUG_ON
    start = time(NULL);
    task_split(n/2+(n%2==1?1:0), 1, hij_process, "Hij_test");
    end = time(NULL);
    INFO("%d threads to calc hij, use %.2f seconds\n", 1, (double)(end-start));
#endif
}

void destroy_global_elemment(void)
{
    int i;
    element_clear(g);
	for(i = 0; i < n; i++)
        element_clear(z[i]);
    free(z);
    pairing_clear(pair);
    pbc_param_clear(par);
}

void show_all_global_element(void)
{
#ifdef DEBUG_ON
    element_printf("g:%B\n", g);
#endif
}
int main(int argc, char *argv[])
{
    INFO("Params generating...\n");
    parse_cmdline(argc, argv);
    if(help)
    {
        show_usage();
        exit(0);
    }
    load_config(config_file);
    //show_config_table();
    nproc = nproc > MAX_PROCESS ? MAX_PROCESS : nproc;
    nproc = nproc > n ? n : nproc;
    INFO("All config is here.\n");
    show_config();
    printf("\n");
    buid_config_dir();
    gen_aparam();
    save_n();
    gene_vdb_param();
    INFO("Save params to file successfully.\n");
    CHECK_RET(SUCCESS == save_params_to_db());
    show_all_global_element();
    destroy_global_elemment();
    INFO("params generate finished.\n");
    return 0;
}
