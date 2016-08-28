#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pbc/pbc.h>
#include <config.h>
#include <debug.h>
#include <vdb.h>

char serip[17] = "127.0.0.1";
int serport = 56789;
int help = 0;
int beinit = -1;
int idx = -1;
int query = -1;
int update = -1;
const char *config_file = "./vdb_client_conf/vdb_client.conf";

char sk_sql_ip[17] = "127.0.0.1";
int  sk_sql_port = 3306;
char sk_sql_user[64] = "root";
char sk_sql_passwd[64] = "letmein";
char sk_sql_dbname[64] = "vdb_client";

char pk_sql_ip[17] = "127.0.0.1";
int  pk_sql_port = 3306;
char pk_sql_user[64] = "root";
char pk_sql_passwd[64] = "letmein";
char pk_sql_dbname[64] = "vdb_server";

struct config config_table[] =
        {
            {"serip", serip, CFG_STR, 17, "i:", "server ip addr."},
            {"serport", &serport, CFG_INT, sizeof(int), "p:", "server port."},
            {"beinit", &beinit, CFG_INT, sizeof(int), "b:", "-b id, id in pk."},
            {"idx", &idx, CFG_INT, sizeof(int), "x:", "x in database."},
            {"query", &query, CFG_INT, sizeof(int), "q:", "query and verify, use -q id -x x"},
            {"sk_sql_ip", sk_sql_ip, CFG_STR, 17, "", "" },
            {"sk_sql_port", &sk_sql_port, CFG_INT, sizeof(int), "", ""},
            {"sk_sql_user", sk_sql_user, CFG_STR, 64, "", "" },
            {"sk_sql_passwd", sk_sql_passwd, CFG_STR, 64, "", "" },
            {"sk_sql_dbname", sk_sql_dbname, CFG_STR, 64, "", "" },
            {"pk_sql_ip", pk_sql_ip, CFG_STR, 17, "", "" },
            {"pk_sql_port", &pk_sql_port, CFG_INT, sizeof(int), "", ""},
            {"pk_sql_user", pk_sql_user, CFG_STR, 64, "", "" },
            {"pk_sql_passwd", pk_sql_passwd, CFG_STR, 64, "", "" },
            {"pk_sql_dbname", pk_sql_dbname, CFG_STR, 64, "", "" },
            {"help", &help, CFG_INT, sizeof(int), "h", "show help."},
            {NULL, NULL, 0, 0, "", NULL}
        };
int connect_server()
{
    int ser = -1;
    struct sockaddr_in ser_addr;
    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(serport);
    ser_addr.sin_addr.s_addr = inet_addr(serip);
    CHECK(ser=socket(AF_INET, SOCK_STREAM, 0));
    CHECK(ser==connect(ser, (struct sockaddr *)&ser_addr, sizeof(struct sockaddr)));
    return ser;
}
/*
 * H0 = (hash(Cf1, C0, T))^y
 * H0,CF1, C0 in G1
 * T is the update times
 * y in ZZp
 */
int hash_HT(element_t H0, element_t y, element_t Cf1, element_t C0, uint64 T)
{
    int len1 = 0;
    int len2 = 0;
    int len3 = 0;
    int len = 0;
    char *buf = NULL;

    len1 = element_length_in_bytes(Cf1);
    len2 = element_length_in_bytes(C0);
    len3 = sizeof(T);
    len += len1;
    len += len2;
    len += len3;

    CHECK_RET(NULL != (buf = (char*) malloc(len)));
    memset(buf, 0, len);
    element_to_bytes(buf, Cf1);
    element_to_bytes(buf+len1, C0);
    memcpy(buf+len1+len2, &T, len3);
    element_from_hash(H0, buf, len);
	element_pow_zn(H0, H0, y);
    free(buf);
	return SUCCESS;
}

void clear_pk_sk(struct vdb_pk *pk, struct vdb_sk *sk)
{
    element_clear(pk->g);
    element_clear(pk->Y);
    element_clear(pk->CR);
    element_clear(sk->y);
}
int vdb_init(int serfd, struct vdb_packet *vpk, struct vdb_pk *pk, struct vdb_sk *sk,
             struct vdb_pair *pair, int id)
{
    element_t H0;
    int ret = FAIL;

    //random select g
    element_init_G1(pk->g, pair->pair);
    element_random(pk->g);

    //element select y
    element_init_Zr(sk->y, pair->pair);
    element_random(sk->y);

    //calculate Y
    element_init_G1(pk->Y, pair->pair);
    element_pow_zn(pk->Y, pk->g, sk->y);

    element_init_G1(pk->CR, pair->pair);
    element_init_G1(H0, pair->pair);

    //begin init send begin and id
    CHECK_GO(SUCCESS == send_val(serfd, vpk, T_I_BEGIN, 0, 0), out2);
    CHECK_GO(SUCCESS == send_val(serfd, vpk, T_I_ID, sizeof(uint32), id), out1);

    //recv CR
    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk), out1);
    CHECK_GO(vpk->type == T_I_CR, out1);
    CHECK_GO(vpk->len == element_from_bytes_compressed(pk->CR, vpk->data), out1);
    CHECK_GO(SUCCESS == hash_HT(H0, sk->y, pk->CR, pk->CR, 0), out1);

    //send H0
    vpk->type = T_I_H0;
    vpk->len = element_length_in_bytes_compressed(H0);
    CHECK_GO(vpk->len <= MAX_DATA_LEN, out1);
    element_to_bytes_compressed(vpk->data, H0);
    CHECK_GO(write_all(serfd, vpk, HEADER_LEN + vpk->len) == vpk->len+HEADER_LEN, out1);

    ret = SUCCESS;
out1:
    element_clear(H0);
out2:
    if(ret != SUCCESS)
        clear_pk_sk(pk, sk);
    return ret;
}


int handle_init(int serfd, int id)
{
    struct vdb_pk *pk = NULL;
    struct vdb_sk *sk = NULL;
    struct vdb_pair *pair = NULL;
    void *conn_pk = NULL;
    void *conn_sk = NULL;
    int beinit = FAIL;;
    int pair_inited = FAIL;
    struct vdb_packet vpk;
    int ret = FAIL;

    DEBUG("Init vdb.\n");
    CHECK_GO(NULL != (conn_pk = (void*)get_connection(pk_sql_ip, pk_sql_port, pk_sql_user, pk_sql_passwd, pk_sql_dbname)), out);
    CHECK_GO(NULL != (conn_sk = (void*)get_connection(sk_sql_ip, sk_sql_port, sk_sql_user, sk_sql_passwd, sk_sql_dbname)), out);
    CHECK_GO(SUCCESS == db_put_str(conn_pk, "vdb_pk", "beinited", "initing", id), out);
    CHECK_GO(pk = (struct vdb_pk*)malloc(sizeof(struct vdb_pk)), out);
    CHECK_GO(sk = (struct vdb_sk*)malloc(sizeof(struct vdb_sk)), out);
    CHECK_GO(pair = (struct vdb_pair*)malloc(sizeof(struct vdb_pair)), out);
    memset(pk, 0, sizeof(struct vdb_pk));
    memset(sk, 0, sizeof(struct vdb_sk));
    memset(pair, 0, sizeof(struct vdb_pair));
    CHECK_GO(SUCCESS == get_pk_first(conn_pk, id, pk), out);
    CHECK_GO(SUCCESS == get_pair(conn_pk, pk->pair_id, pair), out);
    DEBUG("Pair:%p, n:%d, hi:%s, hij:%s\n",
          pair->pair, pair->n, pair->hi_path, pair->hij_path);
    pair_inited = SUCCESS;

    CHECK_GO(SUCCESS == vdb_init(serfd, &vpk, pk, sk, pair, id), out);
    beinit = SUCCESS;
     //save g Y y
    CHECK_GO(SUCCESS == db_put_ele(conn_pk, "vdb_pk", "g", pk->g, id), out);
    CHECK_GO(SUCCESS == db_put_ele(conn_pk, "vdb_pk", "Y", pk->Y, id), out);
    CHECK_GO(SUCCESS == db_put_ele(conn_sk, "vdb_sk", "y", sk->y, id), out);
    CHECK_GO(SUCCESS == db_put_int(conn_pk, "vdb_pk", "CVerTimes", 0, id), out);
    CHECK_GO(SUCCESS == db_put_int(conn_pk, "vdb_pk", "VerTimes", 0, id), out);
    CHECK_GO(SUCCESS == db_put_int(conn_pk, "vdb_pk", "VerProg", -1, id), out);
    CHECK_GO(SUCCESS == db_put_str(conn_pk, "vdb_pk", "VerStatus", "idle", id), out);
#ifdef DEBUG_ON
    //test
    int test=0;
    CHECK_GO(SUCCESS == db_get_ele(conn_pk, "vdb_pk", "g", pk->g, id), out);
    CHECK_GO(SUCCESS == db_get_ele(conn_pk, "vdb_pk", "Y", pk->Y, id), out);
    CHECK_GO(SUCCESS == db_get_ele(conn_sk, "vdb_sk", "y", sk->y, id), out);
    CHECK_GO(SUCCESS == db_get_int(conn_pk, "vdb_pk", "CVerTimes", &test, id), out);
    CHECK_GO(SUCCESS == db_get_int(conn_pk, "vdb_pk", "VerTimes", &test, id), out);
    CHECK_GO(SUCCESS == db_get_int(conn_pk, "vdb_pk", "VerProg", &test, id), out);
    CHECK_GO(SUCCESS == db_get_str(conn_pk, "vdb_pk", "VerStatus", vpk.data, id), out);
#endif

    //send FINISH
    CHECK_GO(SUCCESS == send_val(serfd, &vpk, T_I_CFINISH, 0, 0), out);
    CHECK_GO(SUCCESS == recv_pkt(serfd, &vpk), out);

       //recv server finish
    CHECK_GO(vpk.type == T_I_SFINISH, out);
    CHECK_GO(SUCCESS == db_put_str(conn_pk, "vdb_pk", "beinited", "inited", id), out);
    ret = SUCCESS;

out:
    if(beinit == SUCCESS)           clear_pk_sk(pk, sk);
    if(pair_inited == SUCCESS)      pairing_clear(pair->pair);
    if(conn_pk)                     release_connection(conn_pk);
    if(pair)                        free(pair);
    if(pk)                          free(pk);
    INFO("Init finished.!\n");
    return ret;

}

void handle_query(int serfd, int id)
{
    DEBUG("Query and Verify.\n");
}

void handle_update(int fd)
{
    DEBUG("VDB Update.\n");
}

int main(int argc, char *argv[])
{
    int serfd = -1;
    CHECK(load_config(config_file));
    parse_cmdline(argc, argv);
    if(help)
    {
        show_usage();
        exit(0);
    }
    show_config();
    CHECK(serfd = connect_server());
    if(beinit>=0)
        handle_init(serfd, beinit);
    if(query>=0 && idx>=0)
        handle_query(serfd, idx);
    close(serfd);

    return 0;
}