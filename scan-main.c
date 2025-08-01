
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <postgresql/libpq-fe.h>

#include "masscan_main.h"
#include "db-postgresql.h"
#include "uthash.h" //��ϣ���

#define CACHE_SIZE 1000

int stop_signal = 0;

typedef struct {
    char* ip;
    char* service;
    unsigned port;
}Ipinfo;


int main() {

    CacheManager* manager = create_cache_manager();
    DbConnectInfo db_info;
    db_info.ip = "127.0.0.1";               // ������ַ
    db_info.port = 5432;                    // �˿�
    db_info.db_type = 0;                    // ���ݿ����ͣ�0Ϊpostgresql
    db_info.db_name = "scan";               // ���ݿ�����
    db_info.username = "wsj";               // �û���
    db_info.password = "123456789";         // ����
    PGconn* conn = create_conn(&db_info);
    if (!conn)
    {
        exit(1);
    }
    Masscan_data* data = malloc(sizeof(Masscan_data));
    

    masscan_scan(conn, data, manager);


    return 0;
}

/*
�ȴ���һ�����̣߳�Ȼ�������߳���ִ��masscanɨ��
*/

int masscan_scan(PGconn* conn, Masscan_data* masscan_data, CacheManager* manager)
{/// XXX:��Ҫ�ܹ�����ipv6������
    int pipe_fd[2];         // �ܵ��ļ�������
    pid_t pid;              // ����ID


    // �����ܵ�
    if (pipe(pipe_fd) == -1) {
        perror("�����ܵ�ʧ��");
        exit(EXIT_FAILURE);
    }

    // �����ӽ���
    pid = fork();
    if (pid == -1) {
        perror("�����ӽ���ʧ��");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // �ӽ���
        // �رչܵ�����
        close(pipe_fd[0]);
        // ����׼����ض��򵽹ܵ�д��
        dup2(pipe_fd[1], STDOUT_FILENO);
        // ����׼�������Ҳ�ض��򵽹ܵ����������������
        dup2(pipe_fd[1], STDERR_FILENO);
        // �رչܵ�д��
        close(pipe_fd[1]);
        // ִ�� masscan��ɨ�� 192.168.1.0/24 �� 80 �� 22 �˿ڣ�ʹ�� --output-format=list
        execlp("./a", "a", "-p80,22", "47.122.119.111/24", "--rate=1000", "--banner", "--source-ip", "192.168.71.110", NULL);
        // XXX:��Ҫ�ܹ�����ָ�������Ӳ����

        // ��� execlp ʧ��
        perror("ִ�� masscan ʧ��");
        exit(EXIT_FAILURE);
    }
    else { // ������
        // �رչܵ�д��
        close(pipe_fd[1]);
        // ���ܵ�����ת��Ϊ FILE* ��
        FILE* fp = fdopen(pipe_fd[0], "r");
        if (fp == NULL) {
            perror("ת���ܵ�Ϊ��ʧ��");
            exit(EXIT_FAILURE);
        }
        // char line[MAX_LINE_SIZE];         // ��ȡ�л������������Դ������
        // char ip[MAX_IPV4_SIZE];            // �洢IP��ַ
        // char protocol[MAX_PROTOCOL_SIZE];      // �洢Э��
        // unsigned port;               // �洢�˿ں�

        // char banner[MAX_BANNER_SIZE];
        // char service[MAX_SERVICE_SIZE];
        unsigned count = 0;   //count
        // ���ж�ȡ masscan ���

        


        //masscan_output_format(fp, data, db);



        // ����
        fclose(fp);
        // �ȴ��ӽ��̽���
        wait(NULL);
    }

    return 0;
}

void masscan_output_format(FILE* fp, Masscan_data* data, CacheManager* manager)
//TODO:��Ҫ������ͳ�Ƴ�Ȼ���������ݿ⣬��Ŀǰ���������json�ļ�������
{
    unsigned long count = 0;
    while (fgets(data->line_data, sizeof(data->line_data), fp) != NULL) {
        // ȥ����β���з�
        data->line_data[strcspn(data->line_data, "\n")] = 0;
        // ����Ƿ�Ϊ���Ŷ˿�������� "Discovered open port" ��ͷ��

        if (strncmp(data->line_data, "Discovered open", 15) == 0) {
            printf("ƥ�䵽���Ŷ˿�ɨ��\n");
            // ���Խ�����ʽΪ "Discovered open port %d/%s on %s"
            if (sscanf(data->line_data, "Discovered open  %u %9s %15s", &data->port, data->protocol, data->ipv4) == 3) {
                // �ɹ���������ӡ��ʽ�����
                printf("No.%lu���ֿ��Ŷ˿� - IP: %s, �˿�: %d, Э��: %s\n", ++count, data->ipv4, data->port, data->protocol);
            }
            /*ƥ��bannerɨ��*/
        }
        if (strncmp(data->line_data, "Banner", 6) == 0) {
            printf("ƥ�䵽Bannerɨ��\n");
            if (sscanf(data->line_data, "Banner %u %9s %15s %127s %5119[^\n]", &data->port, data->protocol, data->ipv4, data->service, data->banner) == 5) {
                printf("No.%lu ���ַ��� - IP: %s, �˿�: %d, Э��: %s, ����: %s, Banner: %s\n", ++count, data->ipv4, data->port, data->protocol, data->service, data->banner);
            }
        }

    }
}

