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

typedef struct
{
    char line_data[MAX_LINE_SIZE];
    char ipv4[MAX_IPV4_SIZE];
    char protocol[MAX_PROTOCOL_SIZE];
    char service[MAX_SERVICE_SIZE];
    char banner[MAX_BANNER_SIZE];

    unsigned port;
} Masscan_data;




int masscan_scan(PGconn*, Masscan_data*, CacheManager*);
void masscan_output_format(FILE*, Masscan_data*, CacheManager*);