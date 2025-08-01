#pragma once

#ifndef SCANINFO-CACHE_H

#include <stdlib.h>
#include <stdio.h>
#include "uthash.h"

//#include "db-postgresql.h"

// �˿���Ϣ�ṹ��
typedef struct {
    unsigned short port;
    char* status;
    char* service;
    char* banner;
    char* protocol;
} Info;

// IP��Ŀ�ṹ�壨��ϣ��ڵ㣩
typedef struct {
    char* ip;                    // ��
    Info* infos;                 // �˿���Ϣ����
    char* scanner_name;          // ɨ��������
    unsigned info_count;              // ��ǰ�˿�����
    unsigned info_capacity;           // �˿���������
    UT_hash_handle hh;           // uthash���
} IPEntry;

// ȫ�ֻ������ṹ
typedef struct {
    IPEntry* ip_table;           // ��ϣ��ͷָ��
    unsigned total_records;           // �ܼ�¼��������1000���������жϣ�
} CacheManager;

// //����״̬
// typedef struct {
//     unsigned total;
//     unsigned count;
// }CacheStatus;



CacheManager* create_cache_manager();
IPEntry* create_ip_entry(const char*, unsigned, const char*);
int expend_info_arry(IPEntry*);
int add_data_to_entry(IPEntry*, \
    unsigned short, const char*, const char*, const char*, const char*);
int add_scan_result_to_cache(CacheManager*, const char*, const char*, \
    unsigned short, const char*, const char*, const char*, const char*);
int write_to_database(CacheManager*);
int clear_cache_data(CacheManager*);
int clear_cache_manager(CacheManager*);
unsigned get_cache_status(CacheManager*);

#endif // !SCANINFO-CACHE_H