#include <stdio.h>
#include <debug.h>
#include <pbc/pbc.h>
#include <deftype.h>
#define MAX_STR_LEN 128
#define INITED "inited"
#define UNINIT "uninit"
#define INITING "initing"
#define VER_SUCC "success"
#define VER_FAIL "fail"
#define VER_ING  "verifying"
#define UPD_ING "updating"
#define UPD_FIN "updated"
struct vdb_pk
{
    char ip[17];
    int port;
    char dbname[MAX_STR_LEN];
    char dbtable[MAX_STR_LEN];
    char dbuser[64];
    char dbpassword[32];
    int pair_id;
    element_t CR;
    element_t CT;
    element_t Y;
    char beinited[MAX_STR_LEN];
    int dbsize;
    int CVerTimes;
    int VerTimes;
    char VerStatus[MAX_STR_LEN];
    int VerProg;
};

struct vdb_ss
{
    element_t HT;
    element_t CDTm1;
    element_t CUT;
    uint64 T;
};

struct vdb_pair
{
    pairing_t pair;
    element_t g;
    int n;
    char hi_path[MAX_STR_LEN];
    char hij_path[MAX_STR_LEN];
};

struct vdb_sk
{
    element_t y;
};

struct vdb_proof
{
    element_t paix;
    struct vdb_ss ss;
};

#define HEADER_LEN          5
#define HEADER_VAL_LEN      9
#define MAX_DATA_LEN        128
#define T_I_BEGIN           1
#define T_I_CFINISH         2
#define T_I_ID              3
#define T_I_DBSIZE          4
#define T_I_CR              5
#define T_I_H0              6
#define T_I_SFINISH         7

#define T_Q_BEGIN           8
#define T_Q_ID              9
#define T_Q_X               10
#define T_Q_PAIX            11
#define T_Q_HT              12
#define T_Q_CDTm1           13
#define T_Q_CUT             14
#define T_Q_T               15
#define T_Q_HX              17
#define T_Q_CFINISH         18
#define T_Q_SFINISH         19

#define T_U_BEGIN           20
#define T_U_HT              21
#define T_U_CUT             22
#define T_U_CFINISH         23
#define T_U_SFINISH         24
#define T_U_SQL             25
struct vdb_packet
{
    uint8 type;
    uint32 len;
    union
    {
        int val;
        char data[MAX_DATA_LEN];
    };
}__attribute__((packed));

int send_val(int serfd, struct vdb_packet *vpk, int type, int len, int val);
int send_ele(int client_fd, element_t e, int type, struct vdb_packet *vpk);
int recv_pkt(int serfd, struct vdb_packet *vpk);

struct vdb_resource
{
    struct vdb_packet vpk;
    struct vdb_pk pk;
    struct vdb_sk sk;
    struct vdb_ss ss;
    struct vdb_pair pair;
    void *conn_pk;
    void *conn_sk;
    void *conn_ss;
    void *conn_data;
    int pair_inited;
    element_t paix;
    int ele_inited;
};

struct vdb_config
{
    char sql_ip[17];
    int  sql_port;
    char sql_user[64];
    char sql_passwd[64];
    char sql_dbname[64];
};
#define PK_TB  "vdb_pk"
#define PAIR_TB "vdb_pair"
#define SK_TB "vdb_sk"
#define SS_TB "vdb_s"

int vdb_get_pk_pair(struct vdb_resource *vres, struct vdb_config *pk, int id);
int vdb_client_res_init(struct vdb_resource *vres, struct vdb_config *cli_sk);
struct vdb_resource *get_vdb_resource(void);
int vdb_init_res(struct vdb_resource *vres, struct vdb_config *pk, int id);
int pk_client_init_put(struct vdb_resource *res, int id);
int pk_element_put(struct vdb_resource *res, int id);
void free_vdb_resource(struct vdb_resource *vres);
