
#include "db-postgresql.h"

/**
* �����ͷų�ʼ��sql�����������ڴ�
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
* ���ִ�����������������������res�����һ�ִ������ع���������Ҳ��ζ�����������ݿ���صĲ�����������������С�
*/
static int* to_table(PGconn* conn, PGresult* res, const char* insert_sql, const char* param, int nparmams)
{
	res = PQexecParams(
		conn,
		insert_sql,
		nparmams,
		NULL,
		param,
		0,
		0,
		0
	);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		fprintf(stderr, "ִ��������\n%s\n", PQerrorMessage(conn));
		PQclear(res);
		postgresql_transaction(conn, "ROLLBACK");
		return 0;
	}
	return 1;

}


int postgresql_init(const PGconn* conn)
{
	unsigned short init_sql_count = 4;

	InitDatabaseSQL idbsql;
	idbsql.i_sql = malloc(sizeof(InitDBSQL) * init_sql_count);
	if (!idbsql.i_sql) return 0;

	//TODO:�������sql���
	//BUG:�ƺ�����ʱ�䲻�ԣ�������е�ʱ��
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
	* ����port������������򴴽�
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
	* ����scaninfo��
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

	//BUG:����ʼ�ͽ���ʱ�䲻�ԣ�����Ĭ��

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
		
	//��������
	if (!postgresql_transaction(conn, "BEGIN")) return 0;


	//ִ�д��������
	{
		PGresult* res;
		for (unsigned i = 0; i < init_sql_count; i++)
		{
			res = PQexec(conn, idbsql.i_sql[i].init_sql);
			if (PQresultStatus(res) != PGRES_COMMAND_OK)
			{
				fprintf(stderr, "��ʼ�����ݿ�ʧ�ܣ�\n%s\n\n\n", PQerrorMessage(conn));
				PQclear(res);
				postgresql_transaction(conn, "ROLLBACK");
				fprintf(stderr, "ִ�лع��ɹ���");
				free_init_sql_memory(&idbsql, init_sql_count);
				return 0;
			}
			PQclear(res);
		}
		
	}

	//BUG:��Ҫ�������ִ��ʧ�ܵ����⣬���ύʧ�ܺͻع�ʧ�ܸ�����������ʧ��ֱ���˳���

	//�ύ����
	if (!postgresql_transaction(conn, "COMMIT")) return 0;
	
	free_init_sql_memory(&idbsql, init_sql_count);
	return 1;
}

PGconn* create_conn(DbConnectInfo* info)
{
	PGconn* conn = NULL;

	/*���� db_type ѡ�����ݿ�*/
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
	char* conn_info = ("host=%s port=%u dbname=%s user=%s password=%s", info->ip, info->port, info->db_name, info->username, info->password);

	/*�Զ�����*/
	for (unsigned i = 0; i < retry_times; i++)
	{
		PGconn* conn = PQconnectdb(conn_info);
		if (PQstatus(conn))
		{
			fprintf(stderr, "���������ݿ�ʧ��: %s", PQerrorMessage(conn));
			PQfinish(conn); /*��������*/
			i++;
			//��Ҫ��־
			fprintf(stderr, "�ȴ� %u ��������������ݿ�", sleep_time);
			sleep(sleep_time);
			sleep_time *= 2; //�����ȴ�ʱ��
		}
		else
		{
			return conn;
		}
		
	}
	fprintf(stderr, "����������Դ�������������\n");
	return NULL;
}

/**
* ��ס�����и�other������Ҫ����
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
	
	/*����postgresql���ݿ�������*/
	if (!postgresql_transaction(conn, "BEGIN")) return 0; //��ǰ�˳�

	HASH_ITER(hh, manager->ip_table, entry, temp)
	{
		
		unsigned rows, columns; //�洢���ص��к�������
		{ /*����ips��*/
			const char* sql_param_values[] = { entry->ip }; //��ʱ�������,����asn��isp
			if (!to_table(conn, res, insert_ip_table_sql, sql_param_values, 3)) return 0;
			rows = PQntuples(res);
			columns = PQnfields(res);
			 //NOTE:ͳһʹ�ú����res�����µ�����
		}

		/*��ȡɨ��������*/
		const char* scanner_names = entry->scanner_name;

		{ /*����ports��*/
			unsigned long ip_id = PQgetvalue(res, 0, 0);
			PQclear(res); //��res��ʹ��
			for (unsigned i = 0; i < entry->info_count; i++)
			{
				Info* info = &entry->infos[i];
				const char* sql_param_values1[] = { ip_id, info->port };

				//NOTE:�պ���Ҫ�����ϸע��
				if (!to_table(conn, res, insert_port_table_sql, sql_param_values1, 2)) return 0;
				unsigned long port_id = PQgetvalue(res, 0, 0);
				PQclear(res);

				const char* sql_param_values2[] = { port_id, scanner_names, info->protocol, info->service, info->banner };

				//BUG:����Ҫ����other������jsonb��ʽ

				if (!to_table(conn, res, insert_scan_info_no_other_sql, sql_param_values2, 5)) return 0;
				PQclear(res);

			}
		}
	}
	postgresql_transaction(conn, "COMMIT");
	return 1;
}

int postgresql_transaction(PGconn* conn, const char* type)
{
	PGresult* res = PQexec(conn, type);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, "���� %s ִ��ʧ��\n������Ϣ��\n", *type, PQerrorMessage(conn));
		PQclear(res);
		return 0;
	}
	PQclear(res);
	return 1;
}



