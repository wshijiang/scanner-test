//#pragma once

#ifndef DB_POSTGRESQL_H

#include "postgresql/libpq-fe.h"
#include "scaninfo-cache.h"
#include "common-types.h"

struct CacheManager; // 前向声明CacheManager结构体

#define MAX_RETRY_TIMES 4
#define RETRY_SLEEP_TIME 1 




typedef struct InitDBSQL {
	char* init_sql; //用于存储多个sql语句，且主要用于初始化数据库
}InitDBSQL;

typedef struct InitDatabaseSQL {
	InitDBSQL* i_sql;
}InitDatabaseSQL;

PGconn* connect_to_postgresql(const DbConnectInfo*, const unsigned, unsigned);
PGconn* create_conn(const DbConnectInfo*); // TODO: todo
int postgresql_init(PGconn*);
int insert_batch_data(const PGconn*, const CacheManager*);
#endif // !DB_POSTGRESQL_H