#pragma once

#include "scaninfo-cache.h"

/*
下为处理masscan输出的预设
*/


/*ipv4地址最大空间*/
#define MAX_IPV4_SIZE 16
/*协议最大空间*/
#define MAX_PROTOCOL_SIZE 10
/*banner 最大空间*/
#define MAX_BANNER_SIZE 1024 * 5
/*服务占用空间*/
#define MAX_SERVICE_SIZE 128
/*masscan 输出一行的最大空间*/
#define MAX_LINE_SIZE (MAX_IPV4_SIZE + MAX_PROTOCOL_SIZE + MAX_BANNER_SIZE)

typedef struct Masscan_data
{
    char line_data[MAX_LINE_SIZE];
    char ipv4[MAX_IPV4_SIZE];
    char protocol[MAX_PROTOCOL_SIZE];
    char service[MAX_SERVICE_SIZE];
    char banner[MAX_BANNER_SIZE];

    unsigned port;
} Masscan_data;

typedef struct MasscanConfig
{
    char* masscan_path; // masscan可执行文件路径
    char* banner_scan_ip;
	char* target_ip; // 扫描目标IP
    char* target_port;
    char* rate;      // 扫描速率
} MasscanConfig;;



int masscan_scan(PGconn*, Masscan_data*, CacheManager*, MasscanConfig*);
int masscan_output_format(PGconn*, FILE*, Masscan_data*, CacheManager*, MasscanConfig*, const char*);
int check_masscan_config(MasscanConfig*);
int free_masscan_config(MasscanConfig*);