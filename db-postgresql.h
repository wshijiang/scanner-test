#pragma once

//#ifndef DB-POSTGRESQL_H

#include "postgresql/libpq-fe.h"
#include <unistd.h>
#include "scaninfo-cache.h"



#define MAX_RETRY_TIMES 4
#define RETRY_SLEEP_TIME 1 

typedef struct {
	char* ip;
	unsigned short port;
	char* username;
	char* password;
	char* db_name;
	unsigned db_type;
}DbConnectInfo;


typedef struct {
	char* init_sql; //���ڴ洢���sql��䣬����Ҫ���ڳ�ʼ�����ݿ�
}InitDBSQL;

typedef struct {
	InitDBSQL* i_sql;
}InitDatabaseSQL;

PGconn* connect_to_postgresql(const DbConnectInfo*, const unsigned, unsigned);
PGconn* create_conn(DbConnectInfo*); // TODO: todo
int postgresql_init(const PGconn*);
int insert_batch_data(const PGconn*, const CacheManager*);
//#endif // !DB-POSTGRESQL_H