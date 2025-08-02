
//FIXME:更改注释，初步为 Doxygen
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "scaninfo-cache.h"
#include "db-postgresql.h"



//初始化缓存管理器
CacheManager* create_cache_manager()
{
    CacheManager* manager = malloc(sizeof(CacheManager));
    if (!manager) return NULL;

    manager->ip_table = NULL;
    manager->total_records = 0;
    return manager;
}


/*
* 创建所需ip条目
* @initial_capacity 默认信息数量
*/
IPEntry* create_ip_entry(const char* ip, unsigned initial_capacity, const char* scanner_name)
{
    IPEntry* entry = malloc(sizeof(IPEntry));
    if (!entry) return NULL;

    entry->ip = strdup(ip);
    if (!entry->ip)
    {
        free(entry->ip);
        return NULL;
    }

    entry->infos = (Info*)malloc(initial_capacity * sizeof(Info));
    if (!entry->infos)
    {
        free(entry->ip);
        free(entry);
        return NULL;
    }

    entry->info_capacity = initial_capacity;
    entry->info_count = 0; //已存储的信息条数，创建条目时默认为0
    return entry;
}


/*
* 扩展infos
*/
int expend_info_arry(IPEntry* entry)
{
    unsigned new_capacity = entry->info_capacity * 2;

    Info* new_infos = realloc(entry->infos, new_capacity * sizeof(Info)); //重新分配内存
    if (!new_infos) return 0;

    entry->infos = new_infos;
    entry->info_capacity = new_capacity;

    return 1;
}


/*
* 将数据添加到条目中
*/
int add_data_to_entry(IPEntry* entry, \
    unsigned short port, const char* status, const char* service, const char* protocol, const char* banner)
{
    //检查infos容量是否需要扩容
    if (entry->info_count >= entry->info_capacity)
    {
        if (!expend_info_arry(entry))
        {
            return 0;
        }
    }
    Info* info = &entry->infos[entry->info_count];
    info->port = port;
    info->status = strdup(status);
    info->service = strdup(service);
    info->protocol = strdup(protocol);
    info->banner = strdup(banner);

    if (!info->status || !info->service || !info->protocol || !info->banner)
    {
        free(info->status);
        free(info->service);
        free(info->protocol);
        free(info->banner);

        return 0;
    }

    entry->info_count++;
    return 1;
}


/*
* 将数据添加到缓存中
*/
int add_scan_result_to_cache(CacheManager* manager, const char* ip, const char* scanner_name, \
    unsigned short port, const char* status, const char* service, const char* protocol, const char* banner)
{
    IPEntry* entry;
    HASH_FIND_STR(manager->ip_table, ip, entry);

    if (!entry)
    {
        entry = create_ip_entry(ip, 4, scanner_name);
        if (!entry) return 0;

        /*
        * 向哈希表添加
        * HASH_ADD_KEYPTR接受 hh, 表头, 键, 键的长度, 要添加的项
        */
        HASH_ADD_KEYPTR(hh, manager->ip_table, entry->ip, strlen(entry->ip), entry);
    }

    if (!add_data_to_entry(entry, port, status, service, protocol, banner)) return 0;

    manager->total_records++; //增加记录数量
    return 1;
}

/*
* 将数据写入到数据库中
*/
int write_to_database( PGconn* conn, const CacheManager* manager, const DbConnectInfo* db_info)
{
    //TODO:实现批量写入数据库，如果写入失败则创建一个json文件
    //XXX:

    conn = create_conn(db_info);
    if (!conn)
    {
        return 0;
    }

    if (!postgresql_init(conn))
    {
        return 0;
    }

    if (!insert_batch_data(conn, manager))
    {
        //NOTE:下次添加文件写入方案
        return 0;
    }

    return 1;
}


/*
* 清理缓存数据
*/
int clear_cache_data(CacheManager* manager)
{
    IPEntry* entry, * temp;

    HASH_ITER(hh, manager->ip_table, entry, temp)
    {
        HASH_DEL(manager->ip_table, entry);

        for (int i = 0; i < entry->info_count; i++)
        {
            free(entry->infos[i].status);
            free(entry->infos[i].service);
            free(entry->infos[i].protocol);
            free(entry->infos[i].banner);
        }
        free(entry->infos);
        free(entry->ip);
        free(entry);
    }

    manager->total_records = 0;


    return 1;
}


/*
* 清理缓存管理器
*/
int clear_cache_manager(CacheManager* manager)
{
    if (!manager) return 0;

    clear_cache_data(manager);
    free(manager);
    return 1;
}


/*
* 获取缓存状态
*/
unsigned get_cache_status(CacheManager* manager)
{
    return (manager->total_records, HASH_COUNT(manager->ip_table));
}