#include <stdio.h>
#include <mysql/mysql.h>
#include <openssl/sha.h>

#include <debug.h>

void *get_connection(const char *ip, const char *port, const char *uname,
                      const char *passwd, const char *db)
{
    MYSQL *conn = NULL;
    conn = mysql_real_connect(conn, ip, user, passwd, db, port, NULL, 0);
    return conn;
}

void release_connection(void *conn)
{
    mysql_close((MYSQL *)conn);
}
