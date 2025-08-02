﻿#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include "uthash.h"
#include "postgresql/libpq-fe.h"

// 把 DbConnectInfo 移到这里
typedef struct DbConnectInfo {
    char* ip;
    unsigned short port;
    char* username;
    char* password;
    char* db_name;
    unsigned db_type;
} DbConnectInfo;


// 端口信息结构体
typedef struct Info {
    unsigned short port;
    char* status;
    char* service;
    char* banner;
    char* protocol;
} Info;

// IP条目结构体（哈希表节点）
typedef struct IPEntry {
    char* ip;                    // 键
    Info* infos;                 // 端口信息数组
    char* scanner_name;          // 扫描器名称
    unsigned info_count;              // 当前端口数量
    unsigned info_capacity;           // 端口数组容量
    UT_hash_handle hh;           // uthash句柄
} IPEntry;

// 全局缓存管理结构
typedef struct CacheManager {
    IPEntry* ip_table;           // 哈希表头指针
    unsigned total_records;           // 总记录数（用于1000条批处理判断）
} CacheManager;


#endif
