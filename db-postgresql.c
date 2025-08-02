
#include "db-postgresql.h"
#include <string.h>
#include <unistd.h>

/**
* 用于释放初始化sql语句所分配的内存
*/
static int free_init_sql_memory(InitDatabaseSQL* idbsql, unsigned short count)
{
	if (!idbsql || !idbsql->i_sql || !idbsql->i_sql) return 0;

	for (unsigned short i = 0; i < count; i++)
	{
		free(idbsql->i_sql[i].init_sql);
	}
	free(idbsql->i_sql);

	return 1;
}

/**
* 如果执行遇到错误则会清理掉传入的res。并且会执行事务回滚操作，这也意味着所有与数据库相关的操作必须存在于事务中。
*/
static int to_table(const PGconn* conn, PGresult* res, const char* insert_sql, const char* param, int nparmams)
{
	res = PQexecParams(
		conn,
		insert_sql,
		nparmams,
		NULL,
		&param,
		0,
		0,
		0
	);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		fprintf(stderr, "执行语句错误\n%s\n", PQerrorMessage(conn));
		PQclear(res);
		postgresql_transaction(conn, "ROLLBACK");
		return 0;
	}
	return 1;

}

int postgresql_transaction(PGconn* conn, const char* type)
{
	PGresult* res = PQexec(conn, type);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, "事务 %s 执行失败\n错误信息：%s\n", type, PQerrorMessage(conn));
		PQclear(res);
		return 0;
	}
	PQclear(res);
	return 1;
}

int postgresql_init(const PGconn* conn)
{
	unsigned short init_sql_count = 4;

	InitDatabaseSQL idbsql;
	idbsql.i_sql = malloc(sizeof(InitDBSQL) * init_sql_count);
	if (!idbsql.i_sql) return 0;

	//TODO:完成其他sql语句
	//BUG:似乎更新时间不对，检查所有的时间
	char* init_ips_sql = 
		"CREATE TABLE IF NOT EXISTS ips( "
			"ip_id SERIAL PRIMARY KEY, "
			"ip_address INET NOT NULL UNIQUE,"
			"asn TEXT DEFAULT 'unknown', "
			"isp TEXT DEFAULT 'unknown', "
			"create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,"
			"update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT "
		");";

	/**
	* 创建port表，如果不存在则创建
	*/
	char* init_ports_sql = 
		"CREATE TABLE IF NOT EXISTS ports( "
			"ip_id INT NOT NULL, "
			"port_id SERIAL PRIMARY KEY, "
			"port INT NOT NULL CHECK (port >=0 AND port <= 65535), "
			"create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,"
			"update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, "
			"UNIQUE (ip_id, port), "
			"CONSTRAINT fk_ip "
				"FOREIGN KEY (ip_id) "
				"REFERENCES ips(ip_id) "
				"ON DELETE CASCADE "
				"ON UPDATE CASCADE "
		"); ";


	/**
	* 创建scaninfo表
	*/
	char* init_scaninfo_sql = 
		"CREATE TABLE IF NOT EXISTS scaninfo( "
			"port_id INT NOT NULL, "
			"scan_info_id SERIAL PRIMARY KEY, "
			"scanner_name TEXT NOT NULL, "
			"scan_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,"
			"protocol TEXT DEFAULT NULL, "
			"service TEXT DEFAULT NULL, "
			"banner TEXT, "
			"other JSONB DEFAULT NULL, "
			"UNIQUE (port_id, scan_time), "
			"CONSTRAINT fk_port "
				"FOREIGN KEY (port_id) "
				"REFERENCES ports(port_id) "
				"ON DELETE CASCADE "
				"ON UPDATE CASCADE "
		");";

	//BUG:任务开始和结束时间不对，不能默认

	char* init_scan_task_sql =
		"CREATE TABLE IF NOT EXISTS scan_task( "
			"task_id SERIAL PRIMARY KEY, "
			"task_initiator VARCHAR(10) NOT NULL, "
			"task_target INET NOT NULL, "
			"task_create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, "
			"task_level INT NOT NULL CHECK ( task_level >= 0 AND task_level <=4 ), "
			"task_start_time BIGINT , "
			"task_end_time BIGINT , "
		");";


	idbsql.i_sql[0].init_sql = strdup(init_ips_sql);
	idbsql.i_sql[1].init_sql = strdup(init_ports_sql);
	idbsql.i_sql[2].init_sql = strdup(init_scaninfo_sql);
	idbsql.i_sql[3].init_sql = strdup(init_scan_task_sql);
		
	//开启事务
	if (!postgresql_transaction(conn, "BEGIN")) return 0;


	//执行创建表语句
	{
		PGresult* res;
		for (unsigned i = 0; i < init_sql_count; i++)
		{
			res = PQexec(conn, idbsql.i_sql[i].init_sql);
			if (PQresultStatus(res) != PGRES_COMMAND_OK)
			{
				fprintf(stderr, "初始化数据库失败！\n%s\n\n\n", PQerrorMessage(conn));
				PQclear(res);
				postgresql_transaction(conn, "ROLLBACK");
				fprintf(stderr, "执行回滚成功！");
				free_init_sql_memory(&idbsql, init_sql_count);
				return 0;
			}
			PQclear(res);
		}
		
	}

	//BUG:需要解决事务执行失败的问题，如提交失败和回滚失败该怎样（开启失败直接退出）

	//提交事务
	if (!postgresql_transaction(conn, "COMMIT")) return 0;
	
	free_init_sql_memory(&idbsql, init_sql_count);
	return 1;
}

PGconn* create_conn(const DbConnectInfo* info)
{
	PGconn* conn = NULL;

	/*根据 db_type 选择数据库*/
	switch (info->db_type)
	{
		case 0 :
			conn = connect_to_postgresql(info, MAX_RETRY_TIMES, RETRY_SLEEP_TIME);
			break;
		default :
			conn = connect_to_postgresql(info, MAX_RETRY_TIMES, RETRY_SLEEP_TIME);
	}

	if (!conn) return NULL;

	return conn;
}


PGconn* connect_to_postgresql(const DbConnectInfo* info, const unsigned retry_times, unsigned sleep_time)
{
	//char* conn_info = ("host=%s port=%u dbname=%s user=%s password=%s", info->ip, info->port, info->db_name, info->username, info->password);

	const char* conn_info = malloc(strlen(info->ip) + 20 + strlen(info->db_name) + strlen(info->username) + strlen(info->password));
	sprintf(conn_info, "host=%s port=%u dbname=%s user=%s password=%s", info->ip, info->port, info->db_name, info->username, info->password);
	/*自动重连*/
	for (unsigned i = 0; i < retry_times; i++)
	{
		PGconn* conn = PQconnectdb(conn_info);
		if (PQstatus(conn) != PGRES_COMMAND_OK) //BUG
		{
			fprintf(stderr, "连接至数据库失败: %s", PQerrorMessage(conn));
			PQfinish(conn); /*结束连接*/
			i++;
			//需要日志
			fprintf(stderr, "等待 %u 秒后重新连接数据库", sleep_time);
			sleep(sleep_time);
			sleep_time *= 2; //递增等待时间
		}
		else
		{
			free(conn_info);
			return conn;
		}
		
	}
	fprintf(stderr, "超过最大重试次数，放弃连接\n");
	free(conn_info);
	return NULL;
}

/**
* 记住，还有个other参数需要处理
*/
int insert_batch_data(const PGconn* conn, const CacheManager* manager)
{
	IPEntry* entry, * temp;
	PGresult* res = NULL;

	//const unsigned count = manager->total_records;

	const char* insert_ip_table_sql = 
		"INSERT INTO ips (ip_address, asn, isp) VALUES ( $1, $2, $3 ) RETURNING ip_id;";
	const char* insert_port_table_sql = 
		"INSERT INTO ports ( ip_id, port ) VALUES ( $1, $2) RETURNING port_id;";
	const char* insert_scan_info_sql = 
		"INSERT INTO scaninfo ( port_id, scanner_name, protocol, service, banner, other ) VALUES ( $1, $2, $3, $4, $5, $6 );";
	const char* insert_scan_info_no_other_sql = 
		"INSERT INTO scaninfo ( port_id, scanner_name, protocol, service, banner ) VALUES ( $1, $2, $3, $4, $5 );";
	
	/*开启postgresql数据库事务功能*/
	if (!postgresql_transaction(conn, "BEGIN")) return 0; //提前退出

	HASH_ITER(hh, manager->ip_table, entry, temp)
	{
		
		unsigned rows, columns; //存储返回的行和列数量
		{ /*插入ips表*/
			const char* sql_param_values[] = { entry->ip }; //暂时不管这个,还有asn和isp
			if (!to_table(conn, res, insert_ip_table_sql, sql_param_values, 3)) return 0;
			rows = PQntuples(res);
			columns = PQnfields(res);
			 //NOTE:统一使用后清除res中留下的内容
		}

		/*获取扫描器名称*/
		const char* scanner_names = entry->scanner_name;

		{ /*插入ports表*/
			const char* ip_id = PQgetvalue(res, 0, 0);
			PQclear(res); //该res已使用
			for (unsigned i = 0; i < entry->info_count; i++)
			{
				Info* info = &entry->infos[i];
				char ports[10];
				sprintf(ports, "%d", info->port);
				const char* sql_param_values1[] = { ip_id, ports };

				//NOTE:日后需要添加详细注释
				if (!to_table(conn, res, insert_port_table_sql, sql_param_values1, 2)) return 0;
				const char* port_id = PQgetvalue(res, 0, 0);
				PQclear(res);

				const char* sql_param_values2[] = { port_id, scanner_names, info->protocol, info->service, info->banner };

				//BUG:还需要处理other参数，jsonb格式

				if (!to_table(conn, res, insert_scan_info_no_other_sql, sql_param_values2, 5)) return 0;
				PQclear(res);

			}
		}
	}
	postgresql_transaction(conn, "COMMIT");
	return 1;
}





