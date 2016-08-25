#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include "config.h"

void show_config_table()
{
    int i;
    for(i = 0; config_table[i].name; i++)
        printf("%s %p %d %d\n",
                config_table[i].name, config_table[i].value,
                config_table[i].type, config_table[i].val_len);
}
#define LINE_LEN 1024
static char line[LINE_LEN];
int read_line(FILE *fp, char *data, int len)
{
    int i = 0;
    if(fp == NULL || data == NULL)
    {
        fprintf(stderr, "fp or data is null\n");
        return -1;
    }
    while(i<len)
    {
        data[i]=fgetc(fp);
        if(data[i] == '\n' || data[i] == EOF)
        {
            data[i] = '\0';
            break;
        }
        i++;
    }
    if(i == len)
    {
        fprintf(stderr, "line too long\n");
        return -1;
    }
    return i;
}
int trim_line(char *s, char **s1, char **s2)
{
    int i;
    int flag = 0;
    int n;
    if(s == NULL || s1 == NULL || s2 == NULL)
    {
        fprintf(stderr, "trim_line's param is null.\n");
        return -1;
    }
    for(i = 0; s[i] && flag < 4; i++)
    {
        switch(flag)
        {
            case 0:
                if(s[i]=='#' || s[i] == '=')
                    return -1;
                if(isblank(s[i]))
                    continue;
                *s1 = s+i;
                flag++;
                break;

            case 1:
                if(s[i]=='#')
                    return -1;
                if(isblank(s[i]) || s[i]== '=' )
                {
                    s[i] = '\0';
                    flag++;
                }
                break;
            case 2:
                if(s[i]=='#')
                    return -1;
                if(isblank(s[i]) || s[i] == '=')
                    continue;
                *s2 = s+i;
                flag++;
            case 3:
                if(isblank(s[i]) || s[i]== '#' )
                {
                    s[i] = '\0';
                    flag++;
                }
                break;
        }
    }
    if(s[i] == '\0')
        flag++;
    if(flag == 4 && strlen(*s1)>0 && strlen(*s2) > 0)
        return 0;
    else
        return -1;
}

void parse_value(struct config *cfg, const char *value)
{
    switch(cfg->type)
    {
        case CFG_INT:
            *(int*)cfg->value = atoi(value);
            break;
        case CFG_STR:
            strncpy((char*)(cfg->value), value, cfg->val_len);
            break;
        default:
            fprintf(stderr, "unimplement type.\n");
            break;
    }
}
int parse(const char *name, const char *value)
{
    int i = 0;
    for(i = 0; config_table[i].name; i++)
    {
        if(strcmp(config_table[i].name, name) == 0)
        {
            parse_value(&config_table[i], value);
            return 0;
        }

    }
    return -1;
}
int load_config(const char *config_file)
{
    int ret = 0;
    FILE *fp = NULL;
    char *name, *value;

    if(config_file == NULL)
    {
        fprintf(stderr, "config file is null.\n");
        return -1;
    }
    fp = fopen(config_file, "r");
    if(NULL == fp)
    {
        fprintf(stderr, "open config file failed!\n");
        return -1;
    }

    while(read_line(fp, line, LINE_LEN) > 0)
    {
        //printf("%s\n", line);
        if(trim_line(line, &name, &value) == 0)
        {
           // printf("name:%s\t\tvalue:%s\n", name, value);
            if(parse(name, value) !=0)
                fprintf(stderr, "unmach config:%s =  %s\n", name, value);
        }
    }
    fclose(fp);

    return 0;
}
void show_usage()
{
    int i;
    printf("Usage:\n");
    for(i = 0; config_table[i].name; i++)
    {
        if(config_table[i].opt[1] == ':')
        {
            printf("-%c\t%-15s------ %s:%s\n",
                    config_table[i].opt[0],
                    config_table[i].name,
                    config_table[i].name,
                    config_table[i].usage);
        }
        else
        {
            printf("-%c\t%-15s------ %s:%s\n",
                    config_table[i].opt[0],
                    "",
                    config_table[i].name,
                    config_table[i].usage);
        }
    }
}
int parse_cmdline(int argc, char *argv[])
{
    char *options = NULL;
    int n = 0;
    int size = 0;
    int i;
    int pos;
    int opt;
    int ret  = 0;
    for(i = 0; config_table[i].name; i++)
    {
        n++;
        size++;
        if(config_table[i].opt[1] == ':')
            size++;

    }

    options = (char*)malloc(size);
    if(options == NULL)
    {
        fprintf(stderr, "Error:options malloc failed!\n");
        return -1;
    }

    pos = 0;
    for(i = 0; config_table[i].name; i++)
    {
        strcpy(options+pos, config_table[i].opt);
        pos += strlen(config_table[i].opt);
    }
    options[pos] = '\0';
    while((opt = getopt(argc, argv, options)) != -1)
    {
        for(i = 0; config_table[i].name; i++)
        {
            if(config_table[i].opt[0] == opt)
            {
                if(config_table[i].opt[1] == ':')
                    parse_value(&config_table[i], optarg);
                else
                    parse_value(&config_table[i], "1");
                break;
            }
        }
    }
    free(options);
    return ret;
}

void print_config(const struct config *cfg)
{
    switch(cfg->type)
    {
        case CFG_INT:
            printf("%s: %d\n", cfg->name, *(int*)cfg->value);
            break;
        case CFG_STR:
            printf("%s: %s\n", cfg->name, (char*)cfg->value);
            break;
        default:
            fprintf(stderr, "bad config type, can't print.\n");
    }
}
void show_config()
{
    int i;
    for(i = 0; config_table[i].name; i++)
    {
        print_config(&config_table[i]);
    }
}
