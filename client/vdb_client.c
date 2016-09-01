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
char usql[65536];
const char *config_file = "/etc/vdb_client_conf/vdb_client.conf";
struct vdb_config vcc_sk =
{
    "127.0.0.1",
    3306,
    "root",
    "letmein",
    "vdb_client"
};
struct vdb_config vcc_pk =
{
    "127.0.0.1",
    3306,
    "root",
    "letmein",
    "vdb_client"
};

int ver_status = -1;
struct config config_table[] =
        {
            {"serip", serip, CFG_STR, 17, "i:", "server ip addr."},
            {"serport", &serport, CFG_INT, sizeof(int), "p:", "server port."},
            {"beinit", &beinit, CFG_INT, sizeof(int), "b:", "-b id, id in pk."},
            {"idx", &idx, CFG_INT, sizeof(int), "x:", "x in database."},
            {"query", &query, CFG_INT, sizeof(int), "q:", "query and verify, use -q id -x x"},
            {"update", &update, CFG_INT, sizeof(int), "t:", "-t id -x x -u sql"},
            {"usql", usql, CFG_STR, 65536, "u:", "sql to update." },
            {"sk_sql_ip", vcc_sk.sql_ip, CFG_STR, 17, "", "" },
            {"sk_sql_port", &vcc_sk.sql_port, CFG_INT, sizeof(int), "", ""},
            {"sk_sql_user", vcc_sk.sql_user, CFG_STR, 64, "", "" },
            {"sk_sql_passwd", vcc_sk.sql_passwd, CFG_STR, 64, "", "" },
            {"sk_sql_dbname", vcc_sk.sql_dbname, CFG_STR, 64, "", "" },
            {"pk_sql_ip", vcc_pk.sql_ip, CFG_STR, 17, "", "" },
            {"pk_sql_port", &vcc_pk.sql_port, CFG_INT, sizeof(int), "", ""},
            {"pk_sql_user", vcc_pk.sql_user, CFG_STR, 64, "", "" },
            {"pk_sql_passwd", vcc_pk.sql_passwd, CFG_STR, 64, "", "" },
            {"pk_sql_dbname", vcc_pk.sql_dbname, CFG_STR, 64, "", "" },
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
int hash(element_t H0, element_t Cf1, element_t C0, uint64 T)
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
    free(buf);
	return SUCCESS;
}
int hash_HT(element_t H0, element_t y, element_t Cf1, element_t C0, uint64 T)
{
    CHECK_RET(SUCCESS == hash(H0, Cf1, C0, T));
	element_pow_zn(H0, H0, y);
    return SUCCESS;
}

void clear_pk_sk(struct vdb_pk *pk, struct vdb_sk *sk)
{
    element_clear(pk->Y);
    element_clear(pk->CR);
    element_clear(sk->y);
}
int vdb_init(int serfd, struct vdb_resource *vres, int id)
{
    int ret = FAIL;
    element_t H0;

    element_init_G1(H0, vres->pair.pair);
    //element select y
    element_random(vres->sk.y);
    //calculate Y
    element_pow_zn(vres->pk.Y, vres->pair.g, vres->sk.y);
    //begin init send begin and id
    CHECK_GO(SUCCESS == send_val(serfd, &vres->vpk, T_I_BEGIN, 0, 0), out);
    CHECK_GO(SUCCESS == send_val(serfd, &vres->vpk, T_I_ID, sizeof(uint32), id), out);

    //recv CR
    CHECK_GO(SUCCESS == recv_pkt(serfd, &vres->vpk), out);
    CHECK_GO(vres->vpk.type == T_I_CR, out);
    CHECK_GO(vres->vpk.len == element_from_bytes_compressed(vres->pk.CR, vres->vpk.data), out);
    CHECK_GO(SUCCESS == hash_HT(H0, vres->sk.y, vres->pk.CR, vres->pk.CR, 0), out);

    //send H0
    vres->vpk.type = T_I_H0;
    vres->vpk.len = element_length_in_bytes_compressed(H0);
    CHECK_GO(vres->vpk.len <= MAX_DATA_LEN, out);
    element_to_bytes_compressed(vres->vpk.data, H0);
    CHECK_GO(write_all(serfd, &vres->vpk, HEADER_LEN + vres->vpk.len) == vres->vpk.len+HEADER_LEN, out);

    ret = SUCCESS;
out:
    element_clear(H0);
    return ret;
}


int handle_init(int serfd, int id)
{
    int ret = FAIL;
    struct vdb_resource * vres = NULL;

    CHECK_GO(vres = get_vdb_resource(), out);
    CHECK_GO(SUCCESS == vdb_init_res(vres, &vcc_pk, id), out);
    CHECK_GO(SUCCESS == vdb_client_res_init(vres, &vcc_sk), out);
    CHECK_GO(SUCCESS == db_put_str(vres->conn_pk, "vdb_pk", "beinited", "initing", id), out);
    //get  g  from  database
    CHECK_GO(SUCCESS == db_get_ele(vres->conn_pk, "vdb_pair", "g", vres->pair.g, vres->pk.pair_id), out);

    CHECK_GO(SUCCESS == vdb_init(serfd, vres, id), out);

    CHECK_GO(SUCCESS == pk_client_init_put(vres, id), out);
    CHECK_GO(SUCCESS == db_put_ele(vres->conn_sk, "vdb_sk", "y", vres->sk.y, id), out);
    //send FINISH
    CHECK_GO(SUCCESS == send_val(serfd, &vres->vpk, T_I_CFINISH, 0, 0), out);
    //recv server finish
    CHECK_GO(SUCCESS == recv_pkt(serfd, &vres->vpk), out);
    CHECK_GO(vres->vpk.type == T_I_SFINISH, out);
    CHECK_GO(SUCCESS == db_put_str(vres->conn_pk, "vdb_pk", "beinited", "inited", id), out);
    ret = SUCCESS;

out:
    vdb_rel_vres(vres);
    free_vdb_resource(vres);
    INFO("Init finished.!\n");
    return ret;
}

int vdb_verify(int x, mpz_t v, struct vdb_resource *res, element_t hi)
{
	int b1 = 0, b2 = 0;
    struct vdb_ss *ss = &res->ss;
    struct vdb_pk *pk = &res->pk;
    struct vdb_pair *pair = &res->pair;
	element_t e1,e2, e3, e4, hs, gh,hv, ghhv;
	//e(HT,g)
	element_init_GT(e1, pair->pair);
	element_init_GT(e2, pair->pair);
	element_init_G1(hs, pair->pair);
	pairing_apply(e1, ss->HT, pair->g, pair->pair);
	hash(hs, ss->CDTm1, ss->CUT, ss->T);
	//e(H(CTm1, CT, T), Y)
	pairing_apply(e2, hs, pk->Y, pair->pair);
	b1 = !element_cmp(e1, e2);
	element_clear(e1);
	element_clear(e2);
	element_clear(hs);
	//e(GT/HT*hx^v
    element_init_GT(e3, pair->pair);
	element_init_GT(e4, pair->pair);
	element_init_G1(gh, pair->pair);
	element_init_G1(hv, pair->pair);
	element_init_G1(ghhv, pair->pair);

	element_pow_mpz(hv, hi, v);
	element_div(gh, pk->CT, ss->HT);
	element_div(ghhv, gh, hv);
	pairing_apply(e3, ghhv, hi, pair->pair);

	//e(paix, g)
	pairing_apply(e4, res->paix, pair->g, pair->pair);
	b2 = !element_cmp(e3, e4);
	element_clear(e3);
	element_clear(e4);
	element_clear(gh);
	element_clear(hv);
	element_clear(ghhv);
    return b1 && b2;
}

void vdb_update_client(int x, struct vdb_resource *vres,
                      element_t hi,  mpz_t vx,  mpz_t new_vx);
int handle_query2(int serfd, int id, int x, int opt, char *sql)
{
    int ret = FAIL;
    struct vdb_resource * vres;
    struct vdb_packet *vpk;
    element_t hx;
    mpz_t v;

    DEBUG("Query and Verify.\n");
    mpz_init(v);
    CHECK_GO(vres = get_vdb_resource(), out);
    vpk = &vres->vpk;
    CHECK_GO(SUCCESS == vdb_init_res(vres, &vcc_pk, id), out2);
    element_init_G1(hx, vres->pair.pair);
    CHECK_GO(SUCCESS == vdb_client_res_init(vres, &vcc_sk), out);
    CHECK_GO(SUCCESS == pk_element_get(vres, id), out);
    CHECK_GO(SUCCESS == db_get_ele(vres->conn_pk, "vdb_pair", "g", vres->pair.g, vres->pk.pair_id), out);
    CHECK_GO(SUCCESS == sk_element_get(vres, id), out);
    CHECK_GO(SUCCESS == db_get_str(vres->conn_pk, "vdb_pk", "beinited", vpk->data, id), out);
    CHECK_GO(strcmp(INITED, vpk->data) == 0, out);
    CHECK_GO(SUCCESS == db_put_str(vres->conn_pk, "vdb_pk", "VerStatus", VER_ING, id), out);

    //send BEGIN ID x
    CHECK_GO(SUCCESS == send_val(serfd, vpk, T_Q_BEGIN, 0, 0), out);
    CHECK_GO(SUCCESS == send_val(serfd, vpk, T_Q_ID, sizeof(int), id), out);
    x = x < 0 ? rand()% vres->pk.dbsize : x;
    CHECK_GO(SUCCESS == send_val(serfd, vpk, T_Q_X, sizeof(int), x), out);
    CHECK_GO(SUCCESS == db_getv(vres->conn_data, vres->pk.dbtable, x, v), out);
    //recv PAIX HT CDTm1 CUT T
    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_PAIX, out);
    CHECK_GO(element_from_bytes_compressed(vres->paix, vpk->data) == vpk->len, out);

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_HT, out);
    CHECK_GO(element_from_bytes_compressed(vres->ss.HT, vpk->data) == vpk->len, out);

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_CDTm1, out);
    CHECK_GO(element_from_bytes_compressed(vres->ss.CDTm1, vpk->data) == vpk->len, out);

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_CUT, out);
    CHECK_GO(element_from_bytes_compressed(vres->ss.CUT, vpk->data) == vpk->len, out);

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_HX, out);
    CHECK_GO(element_from_bytes_compressed(hx, vpk->data) == vpk->len, out);

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_Q_T, out);
    CHECK_GO(vpk->len == sizeof(uint64), out);
    vres->ss.T = *(uint64*)vpk->data;
    if(vdb_verify(x, v, vres, hx))
    {
        CHECK_GO(SUCCESS == db_put_str(vres->conn_pk, "vdb_pk", "VerStatus", VER_SUCC, id), out);
        INFO("Verify Successfully!\n");
        ver_status = 1;
    }
    else
    {
        CHECK_GO(SUCCESS == db_put_str(vres->conn_pk, "vdb_pk", "VerStatus", VER_FAIL, id), out);
        INFO("Verify Failed!\n");
        ver_status = 2;
    }

    CHECK_GO(SUCCESS == recv_pkt(serfd, vpk), out);
    CHECK_GO(vpk->type == T_Q_SFINISH, out);
    CHECK_GO(ver_status == 1, out);
    if(opt)
    {
        int sql_len = 0;
        ret = FAIL;
        mpz_t vt;
        mpz_init(vt);
        ret = FAIL;
        INFO("Update Begin.\n");
        CHECK_GO(SUCCESS == db_getv_vt(vres->conn_data, vres->pk.dbtable, sql, x, vt), out1);
        vdb_update_client(x, vres, hx, v, vt);
        CHECK_GO(SUCCESS == send_val(serfd, vpk, T_U_BEGIN, 0, 0), out1);
        CHECK_GO(SUCCESS == send_ele(serfd, vres->ss.HT, T_U_HT, vpk), out1);
        CHECK_GO(SUCCESS == send_ele(serfd, vres->ss.CUT, T_U_CUT, vpk), out1);
        sql_len = strlen(sql);
        vpk->type = T_U_SQL;
        vpk->len = sql_len;
        CHECK_GO(write_all(serfd, vpk, HEADER_LEN) == HEADER_LEN, out1);
        CHECK_GO(write_all(serfd, sql, sql_len) == sql_len, out1);
        CHECK_GO(SUCCESS == recv_pkt(serfd, vpk) && vpk->type == T_U_SFINISH, out1);
        CHECK_GO(SUCCESS == send_val(serfd, vpk, T_U_CFINISH, 0, 0), out);
        ret = SUCCESS;
        ver_status = SUCCESS;
        INFO("Update Successfully.\n");
    out1:
        mpz_clear(vt);
    }
    else
    {
        CHECK_GO(SUCCESS == send_val(serfd, vpk, T_Q_CFINISH, 0, 0), out);
        ret = SUCCESS;
    }
out:
    element_clear(hx);
out2:
    mpz_clear(v);
    vdb_rel_vres(vres);
    free_vdb_resource(vres);
    INFO("Query finished.!\n");
    return ret;
}
int handle_query(int serfd, int id, int x)
{
    return handle_query2(serfd, id, x, 0, NULL);
}
void vdb_update_client(int x, struct vdb_resource *vres,
                      element_t hi,  mpz_t vx,  mpz_t new_vx)
{
	element_t ch, hv, hv2,  new_CT, hs, new_HT;
    struct vdb_pair *pair = &vres->pair;
    struct vdb_pk *pk = &vres->pk;
    struct vdb_sk *sk = &vres->sk;
    struct vdb_ss *ss = &vres->ss;

	element_init_G1(ch, pair->pair);
	element_init_G1(hv, pair->pair);
	element_init_G1(hv2, pair->pair);
	element_init_G1(new_CT, pair->pair);

	element_div(ch, pk->CT, ss->HT); //ch = CT-1/HT-1
	element_pow_mpz(hv, hi, vx); //hv = hx^v
	element_pow_mpz(hv2, hi, new_vx); //hv = hx^v
    element_div(hv, hv, hv2);
	element_div(new_CT, ch, hv);       //CT=ch * hv

	element_clear(ch);
	element_clear(hv);
	element_clear(hv2);

	element_init_G1(hs, pair->pair);
	element_init_G1(new_HT, pair->pair);

	hash(hs, pk->CT, new_CT, ss->T+1);	//hs=hash(CT-1, CT, T)
	element_pow_zn(new_HT, hs, sk->y);  //HT = hs^y


	element_set(ss->HT, new_HT);
    element_set(ss->CUT, new_CT);
	//ss->T = new_T;

	element_clear(new_CT);
	element_clear(hs);
	element_clear(new_HT);
}

int handle_update(int fd, int id, char *sql, int x)
{
    DEBUG("VDB Update.\n");
    return handle_query2(fd, id, x, 1, sql);
}

int main(int argc, char *argv[])
{
    int serfd = -1;
    srand(time(NULL));
    CHECK(load_config(config_file));
    parse_cmdline(argc, argv);
    if(help)
    {
        show_usage();
        exit(0);
    }
#ifdef DEBUG_ON
    show_config();
#endif
    CHECK(serfd = connect_server());
    if(beinit>=0)
    {
        handle_init(serfd, beinit);
        ver_status = 0;
    }
    else  if(query>=0)
    {
        handle_query(serfd, query, idx);
    }
    else  if(update>=0 && strlen(usql)>0 && idx>=0)
    {
        INFO("update...\n");
       handle_update(serfd, update, usql, idx);
    }
    close(serfd);
    mysql_thread_end();
    return ver_status;
}
