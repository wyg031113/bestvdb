#ifndef __CONFIG_H__
#define __CONFIG_H__
#define CFG_INT 1
#define CFG_STR 2
struct config
{
    const char *name;
    void *value;
    char type;
    int val_len;
    char opt[3];
    char *usage;
};
extern struct config config_table[];
void show_config_table();
void show_config();
int parse_cmdline(int argc, char *argv[]);
int load_config(const char *config_file);
#endif /*__CONFIG_H__*/
