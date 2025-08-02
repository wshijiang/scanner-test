//#pragma once



#ifndef SCANINFO_CACHE_H


#include <stdlib.h>
#include <stdio.h>
#include "postgresql/libpq-fe.h"
#include "uthash.h"
//#include "db-postgresql.h"

typedef struct DbConnectInfo DbConnectInfo; // 前向声明DbConnectInfo结构体


// 端口信息结构体
typedef struct {
    unsigned short port;
    char* status;
    char* service;
    char* banner;
    char* protocol;
} Info;

// IP条目结构体（哈希表节点）
typedef struct {
    char* ip;                    // 键
    Info* infos;                 // 端口信息数组
    char* scanner_name;          // 扫描器名称
    unsigned info_count;              // 当前端口数量
    unsigned info_capacity;           // 端口数组容量
    UT_hash_handle hh;           // uthash句柄
} IPEntry;

// 全局缓存管理结构
typedef struct {
    IPEntry* ip_table;           // 哈希表头指针
    unsigned total_records;           // 总记录数（用于1000条批处理判断）
} CacheManager;


CacheManager* create_cache_manager();
IPEntry* create_ip_entry(const char*, unsigned, const char*);
int expend_info_arry(IPEntry*);
int add_data_to_entry(IPEntry*, \
    unsigned short, const char*, const char*, const char*, const char*);
int add_scan_result_to_cache(CacheManager*, const char*, const char*, \
    unsigned short, const char*, const char*, const char*, const char*);
int write_to_database(PGconn*, const CacheManager*, const DbConnectInfo*);
int clear_cache_data(CacheManager*);
int clear_cache_manager(CacheManager*);
unsigned get_cache_status(CacheManager*);

#endif // !SCANINFO_CACHE_H