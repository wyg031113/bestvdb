#include <stdio.h>
#include <pbc/pbc.h>
#include <mysql/mysql.h>
#include <openssl/sha.h>
#include <string.h>
#include <memory.h>
#include <debug.h>
#include <vdb.h>
#include <db.h>

void *get_connection(const char *ip, int port, const char *uname,
                      const char *passwd, const char *db)
{
    MYSQL *conn = NULL;
    conn = mysql_init(NULL);
    if(!conn)
        return conn;
    conn = mysql_real_connect(conn, ip, uname, passwd, db, port, NULL, 0);
    return conn;
}
int element_to_str(const char *ename, element_t ele, char *e_str)
{
    char data[MAX_DATA_LEN];
    int n;
    int i;
    int rv = 0;
    int len = 0;
    if(strcmp(ename,"y") == 0)
        n = element_length_in_bytes(ele);
    else
        n = element_length_in_bytes_compressed(ele);
  // element_printf("n = %d, %s=%B\n", n, ename, ele);
    CHECK_RET(n <= MAX_DATA_LEN);
    if(strcmp(ename,"y") == 0)
        element_to_bytes(data, ele);
    else
        element_to_bytes_compressed(data, ele);

    for(i = 0; i < n; i++, len+=2)
        snprintf(e_str+len, 3, "%02x", (unsigned char)data[i]);
    e_str[len] = '\0';
    return SUCCESS;
}

int str_to_element(const char *ename, element_t ele, const char *e_str)
{
    int i;
    unsigned int d;
    unsigned char tx[3];
    char data[MAX_DATA_LEN+2];
    int n = strlen(e_str);
    CHECK_RET(n/2<MAX_DATA_LEN);
   for(i = 0; i < n; i+=2)
    {
        tx[0] =  e_str[i];
        tx[1] = e_str[i+1];
        tx[2] = 0;
        sscanf(tx,"%x",&d);
        data[i/2] = (uint8)d;
    }
   data[i/2] = 0;
    if(strcmp(ename,"y") == 0)
        element_from_bytes(ele, data);
    else
        element_from_bytes_compressed(ele, data);
    element_printf("%s=%B\n", ename, ele);
    return SUCCESS;

}
int insert_pair(void *connection, char *pair, element_t g, int n, char *hi, char *hij)
{
    MYSQL *mysql = (MYSQL*)connection;
    int len = strlen(pair)+strlen(hi)+strlen(hij)+10+128;
    int ret = FAIL;
    char *sql;
    char e_str[MAX_DATA_LEN*2+1];
    CHECK_GO(element_to_str("g", g, e_str) == SUCCESS, out);
    len += strlen(e_str);
    CHECK_RET(sql = malloc(len));

    snprintf(sql, len, "insert into vdb_pair(pair, g, n, hi_path, hij_path) values('%s','%s','%d','%s','%s')",
                        pair, e_str, n, hi, hij);
    if(!mysql_query(mysql, sql))
        ret = SUCCESS;
out:
    free(sql);
    return ret;
}

int get_pk_first(void *connection, int id, struct vdb_pk *pk)
{
    MYSQL *conn = (MYSQL*)connection;
    char sql[256];
    int i;
    int ret;
    int ret_val = FAIL;
    int pair_id = -1;
    void *vals[] = {pk->ip, &pk->port, pk->dbname, pk->dbtable, pk->dbuser,
                    pk->dbpassword, &pk->pair_id, pk->beinited, &pk->dbsize,
                    &pk->CVerTimes, &pk->VerTimes, pk->VerStatus, &pk->VerProg
                    };
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    MYSQL_FIELD *field;
    ASSERT(pk != NULL);
    snprintf(sql, 256, "select ip,port,dbname,dbtable,dbuser,dbpassword,"
             "pair_id, beinited,dbsize,CVerTimes,VerTimes,VerStatus,"
             "VerProg from vdb_pk where id = %d", id);
    CHECK_RET(!(ret = mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    for(i = 0; i < 13; i++)
    {
        field = mysql_fetch_field_direct(res, i);
        DEBUG("Field:%d is %s\n", i, field->name);
        if(row[i] == NULL)
        {
            DEBUG("field:%s is NULL\n", field->name);
            continue;
        }
        if(IS_NUM(field->type))
        {
            *(int*)vals[i] = atoi(row[i]);
            DEBUG("VAL:%d\n", *(int*)vals[i]);
        }
        else
        {
            CHECK_GO(strlen(row[i]) < MAX_STR_LEN, out1);
            strcpy((char*)vals[i], row[i]);
            DEBUG("VAL:%s\n", (char*)vals[i]);
        }

    }
    ret_val = SUCCESS;
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return ret_val;

}

int get_pair(void *connection, int pair_id, struct vdb_pair *pair)
{
    char sql[MAX_SQL_LEN];
    int i;
    int ret;
    int ret_val = FAIL;
    MYSQL *conn = (MYSQL *)connection;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    MYSQL_FIELD *field;
    ASSERT(pair != NULL);
    snprintf(sql, MAX_SQL_LEN, "select pair, n, hi_path, hij_path from vdb_pair where id = %d", pair_id);
    CHECK_RET(!(ret = mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    for(i = 0; i < 5; i++)
    {
        CHECK_GO(row[i], out1);
        field = mysql_fetch_field_direct(res, i);
        if(i!=0 && !IS_NUM(field->type))
            CHECK_GO(strlen(row[i]) <  MAX_STR_LEN, out1);

    }
    CHECK_GO(!pairing_init_set_str(pair->pair, row[0]), out1);
    pair->n = atoi(row[1]);
    strcpy(pair->hi_path, row[2]);
    strcpy(pair->hij_path, row[3]);

    ret_val = SUCCESS;
out0:
    if(ret_val == FAIL)
        pairing_clear(pair->pair);
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return ret_val;


}
int db_exist(void *connection, const char *table, int id)
{
    int ret = FAIL;
    char sql[MAX_SQL_LEN];
    MYSQL *conn = (MYSQL*)connection;
    MYSQL_RES * res = NULL;
    MYSQL_ROW row;
    snprintf(sql, MAX_SQL_LEN, "select * from %s where id = %d", table, id);
    CHECK_RET(!mysql_query(conn, sql));
    CHECK_RET(res = mysql_use_result(conn));
    row = mysql_fetch_row(res);
    if(row != NULL)
        ret = SUCCESS;
    mysql_free_result(res);
    return ret;
}
int db_put_ele(void *connection, const char *table, const char *ename, element_t ele, int id)
{
    char sql[MAX_SQL_LEN];
    char e_str[MAX_DATA_LEN*2+1];
    CHECK_RET(SUCCESS == element_to_str(ename, ele, e_str));
    MYSQL *conn = (MYSQL*)connection;
    if(FAIL == db_exist(connection, table, id))
        snprintf(sql, MAX_SQL_LEN, "insert into %s(id, %s) values('%d', '%s')",table, ename, id, e_str);
    else
        snprintf(sql, MAX_SQL_LEN, "update %s set %s = '%s' where id = '%d'", table, ename, e_str, id);
    CHECK_RET(!mysql_query(conn, sql));
    return  SUCCESS;
}

int db_get_ele(void *connection, const char *table, const char *ename, element_t ele, int id)
{
    char sql[MAX_SQL_LEN];
    int ret = FAIL;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    MYSQL *conn = (MYSQL*)connection;
    element_snprintf(sql, MAX_SQL_LEN, "select  %s from %s where id = '%d'", ename, table, id);
    CHECK_RET(!(mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    CHECK_GO(row[0], out2);
    CHECK_GO(SUCCESS == str_to_element(ename, ele, row[0]), out1);
    ret = SUCCESS;
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return  ret;
}

int db_put_int(void *connection, const char *table, const char *ename, int val, int id)
{
    char sql[MAX_SQL_LEN];
    MYSQL *conn = (MYSQL*)connection;
    DEBUG("PutInt:%d\n", val);
    snprintf(sql, MAX_SQL_LEN, "update %s set %s = '%d' where id = '%d'", table, ename, val, id);
    CHECK_RET(!mysql_query(conn, sql));

    return  SUCCESS;
}

int db_get_int(void *connection, const char *table, const char *ename, int *val, int id)
{
    char sql[MAX_SQL_LEN];
    int ret = FAIL;
    MYSQL_RES *res = NULL;
    MYSQL_FIELD *field = NULL;
    MYSQL_ROW row;
    MYSQL *conn = (MYSQL*)connection;
    element_snprintf(sql, MAX_SQL_LEN, "select  %s from %s where id = '%d'", ename, table, id);
    CHECK_RET(!(mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    CHECK_GO(field = mysql_fetch_fields(res), out2);
    CHECK_GO(row[0], out2);
    *val = atoi(row[0]);

    DEBUG("GetInt:%d\n", *(uint32*)val);
    ret = SUCCESS;
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return  ret;
}
int db_put_int64(void *connection, const char *table, const char *ename, int64 val, int id)
{
    char sql[MAX_SQL_LEN];
    MYSQL *conn = (MYSQL*)connection;
    DEBUG("PutInt:%lld\n", val);
    snprintf(sql, MAX_SQL_LEN, "update %s set %s = '%lld' where id = '%d'", table, ename, val, id);
    CHECK_RET(!mysql_query(conn, sql));

    return  SUCCESS;
}

int db_get_int64(void *connection, const char *table, const char *ename, int64 *val, int id)
{
    char sql[MAX_SQL_LEN];
    int ret = FAIL;
    MYSQL_RES *res = NULL;
    MYSQL_FIELD *field = NULL;
    MYSQL_ROW row;
    MYSQL *conn = (MYSQL*)connection;
    element_snprintf(sql, MAX_SQL_LEN, "select  %s from %s where id = '%d'", ename, table, id);
    CHECK_RET(!(mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    CHECK_GO(field = mysql_fetch_fields(res), out2);
    CHECK_GO(row[0], out2);
    *val = atoll(row[0]);

    DEBUG("GetInt:%lld\n", *val);
    ret = SUCCESS;
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return  ret;
}


int db_put_str(void *connection, const char *table, const char *ename, const char *val, int id)
{
    char sql[MAX_SQL_LEN+MAX_STR_LEN];
    DEBUG("PutStr:%s\n", val);
    MYSQL *conn = (MYSQL*)connection;
    snprintf(sql, MAX_SQL_LEN+MAX_STR_LEN, "update %s set %s = '%s' where id = '%d'", table, ename, val, id);
    CHECK_RET(!mysql_query(conn, sql));
    return  SUCCESS;
}

int db_get_str(void *connection, const char *table, const char *ename, char *val, int id)
{
    char sql[MAX_SQL_LEN];
    int ret = FAIL;
    MYSQL_RES *res = NULL;
    MYSQL_FIELD *field = NULL;
    MYSQL_ROW row;
    MYSQL *conn = (MYSQL*)connection;
    element_snprintf(sql, MAX_SQL_LEN, "select  %s from %s where id = '%d'", ename, table, id);
    CHECK_RET(!( mysql_query(conn, sql)));
    CHECK_RET(res = mysql_use_result(conn));
    CHECK_GO(row = mysql_fetch_row(res), out2);
    CHECK_GO(field = mysql_fetch_fields(res), out2);
    CHECK_GO(row[0], out2);
    CHECK_GO(strlen(row[0]) < MAX_STR_LEN, out1);
    strcpy(val, row[0]);
    DEBUG("GetStr:%s\n", val);
    ret = SUCCESS;
out1:
    while(NULL != (mysql_fetch_row(res)));
out2:
    mysql_free_result(res);
    return  ret;
}

int hash_rows(char *md, char** row, unsigned long *lens, int nrow)
{
    int i;
    SHA_CTX stx;
    SHA_Init(&stx);
    for(i = 0; i < nrow; i++)
        if(NULL != row[i])
            SHA_Update(&stx, row[i], lens[i]);
    SHA_Final(md, &stx);
    /*
    for(i = 0; i < 20; i++)
        printf("%02x", (unsigned char)md[i]);
    printf("\n");
    */
    return 0;
}

int db_getv(void *connection, const char *table, int x, mpz_t v)
{
    int i;
    int ret = FAIL;
    char sql[MAX_SQL_LEN];
    char md[128];
    char md_str[256];
    int len = 0;
    unsigned long *lens = NULL;
    MYSQL *conn = (MYSQL *)connection;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;

    snprintf(sql, MAX_SQL_LEN, "select * from %s where id = %d",
            table, x+1);
    CHECK_RET(0 == mysql_query(conn, sql));
    CHECK_RET(NULL != (res = mysql_use_result(conn)));
    CHECK_GO(row = mysql_fetch_row(res), out);
    CHECK_GO(NULL != (lens = mysql_fetch_lengths(res)), out);
    hash_rows(md, row, lens, res->field_count);
    for(i = 0; i < 20 && len < 256; i++, len+=2)
        snprintf(md_str+len, 3, "%02x", (unsigned char)md[i]);
    mpz_set_str(v, md_str, 16);
    ret = SUCCESS;
    mpz_out_str(stdout, 10, v);
out:
    if(res != NULL)     mysql_free_result(res);
    return ret;
}



void release_connection(void *conn)
{
    mysql_close((MYSQL *)conn);
}
int test_main()
{
    void *conn = NULL;
    CHECK2(NULL != (conn = get_connection("127.0.0.1", 3306, "root", "letmein", "vdb_server")));
//int insert_pai(void *connection, char *pair, int n, char *hi, char *hij)
    char pa[] = "I am pair.....";
    char hix[] = "a/b/chi";
    char hij[] = "a/b/chij";
    char n[] = "2323";
    /*CHECK2(SUCCESS == insert_pair(conn, pa, 2323, hix, hij));
    struct vdb_pk pk;
    struct vdb_pair pair;
    get_pk_first(conn, 1, &pk);
    get_pair(conn, 1, &pair);
    DEBUG("Pair:%p, n:%d, hi:%s, hij:%s\n",
          pair.pair, pair.n, pair.hi_path, pair.hij_path);
    //get_pair(conn, 1, NULL);
    release_connection(conn);
    */
}
