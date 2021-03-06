#ifndef __DB_H__
#define __DB_H__
#define MAX_SQL_LEN 256
void *get_connection(const char *ip, int port, const char *uname,
                      const char *passwd, const char *db);

int str_to_element(const char *ename, element_t ele, const char *e_str);
int element_to_str(const char *ename, element_t ele, char *e_str);
int db_getv(void *connection, const char *table, int x, mpz_t v);
int insert_pair(void *connection, char *pair, element_t g, int n, char *hi, char *hij);
int get_pk_first(void *connection, int id, struct vdb_pk *pk);
int get_pair(void *connection, int pair_id, struct vdb_pair *pair);
int db_put_ele(void *connection, const char *table, const char *ename, element_t ele, int id);
int db_get_ele(void *connection, const char *table, const char *ename, element_t ele, int id);
int db_put_int(void *connection, const char *table, const char *ename, int val, int id);
int db_get_int(void *connection, const char *table, const char *ename, int *val, int id);
int db_get_int64(void *connection, const char *table, const char *ename, int64 *val, int id);
int db_put_int64(void *connection, const char *table, const char *ename, int64 val, int id);
int db_put_str(void *connection, const char *table, const char *ename, const char *val, int id);
int db_get_str(void *connection, const char *table, const char *ename, char *val, int id);
int db_getv_vt(void *connection, const char *table, const char *sql, int x, mpz_t vt);
int db_query(void *connection, const char *sql);
void release_connection(void *conn);
#endif /*__DB_H__*/
