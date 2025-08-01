#pragma once

#include "scaninfo-cache.h"

/*
��Ϊ����masscan�����Ԥ��
*/



/*ipv4��ַ���ռ�*/
#define MAX_IPV4_SIZE 16
/*Э�����ռ�*/
#define MAX_PROTOCOL_SIZE 10
/*banner ���ռ�*/
#define MAX_BANNER_SIZE 1024 * 5
/*����ռ�ÿռ�*/
#define MAX_SERVICE_SIZE 128
/*masscan ���һ�е����ռ�*/
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