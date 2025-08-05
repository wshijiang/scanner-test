﻿
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <postgresql/libpq-fe.h>
#include <signal.h>

#include "masscan_main.h"
#include "db-postgresql.h"
//#include "uthash.h" //哈希表库


void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        stop_signal = 1;
        printf("收到停止信号，正在清理资源...\n");
        // 可以在这里添加清理代码
    }
}

int sign_signal_func()
{
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("无法捕获 SIGINT 信号\n");
        return 0;
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        perror("无法捕获 SIGTERM 信号\n");
        return 0;
    }
    return 1;
}




int main(int argc, char* argv[]) {
    if (argc != 6) return 0;
	setbuf(stdout, NULL); // 禁用缓冲，确保输出立即显示
    if (!sign_signal_func) return 0;
    printf("开始\n");

    CacheManager* manager = create_cache_manager();
    DbConnectInfo db_info;
    db_info.ip = "127.0.0.1";               // 主机地址
    db_info.port = 54321;                   // 端口
    db_info.db_type = 0;                    // 数据库类型，0为postgresql
    db_info.db_name = "scan";               // 数据库名称
    db_info.username = "wsj";               // 用户名
    db_info.password = "123456789";         // 密码
    PGconn* conn = create_conn(&db_info);
    if (!conn)
    {
        clear_cache_manager(manager);
        exit(1);
    }
    if (!postgresql_init(conn))
    {
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    }

    Masscan_data* data = malloc(sizeof(Masscan_data));
    if (!data)
    {
		fprintf(stderr, "Masscan data内存分配失败\n");
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    } 
	MasscanConfig* masscan_config = malloc(sizeof(MasscanConfig));
    if (!check_masscan_config(masscan_config))
    {
        free_masscan_config(masscan_config);
        return 0;
    }



    masscan_config->target_ip = strdup(argv[1]);
    masscan_config->target_port = strdup(argv[2]);
    masscan_config->masscan_path = strdup(argv[5]);
    masscan_config->banner_scan_ip = strdup(argv[4]);
    masscan_config->rate = strdup(argv[3]);
    
    if (!stop_signal)
    {
        masscan_scan(conn, data, manager, masscan_config);
        printf("扫描完成\n");
    }
    

	

    /**
    * 清理分配的内存
    */
    free(data);
    PQfinish(conn);
    clear_cache_manager(manager);
    free_masscan_config(masscan_config);

    return 0;
}

/*
先创建一个子线程，然后在子线程中执行masscan扫描
*/

int masscan_scan(PGconn* conn, Masscan_data* masscan_data, CacheManager* manager, MasscanConfig* masscan_config)
{/// XXX:需要能够接受ipv6并处理
    int pipe_fd[2];         // 管道文件描述符
    pid_t pid;              // 进程ID


    // 创建管道
    if (pipe(pipe_fd) == -1) {
        perror("创建管道失败");
        exit(EXIT_FAILURE);
    }

    // 创建子进程
    pid = fork();
    if (pid == -1) {
        perror("创建子进程失败");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // 子进程
        // 关闭管道读端
        close(pipe_fd[0]);
        // 将标准输出重定向到管道写端
        dup2(pipe_fd[1], STDOUT_FILENO);
        // 将标准错误输出也重定向到管道（捕获所有输出）
        dup2(pipe_fd[1], STDERR_FILENO);
        // 关闭管道写端
        close(pipe_fd[1]);
        // 执行 masscan，扫描 192.168.1.0/24 的 80 和 22 端口，使用 --output-format=list
        execlp("./a", "a", "-p80,22", masscan_config->target_ip, "--rate=1000", "--banner", "--source-ip", masscan_config->banner_scan_ip, NULL);
        // XXX:需要能够接受指令，而不是硬编码

        // 如果 execlp 失败
        perror("执行 masscan 失败");
        exit(EXIT_FAILURE);
    }
    else { // 父进程
        // 关闭管道写端
        close(pipe_fd[1]);
        // 将管道读端转换为 FILE* 流
        FILE* fp = fdopen(pipe_fd[0], "r");
        if (fp == NULL) {
            perror("转换管道为流失败");
            exit(EXIT_FAILURE);
        }


        if (!masscan_output_format(conn, fp, masscan_data, manager))
        {
            fclose(fp);
			wait(NULL); // 等待子进程结束
            return 0;
        }

        // 清理
        fclose(fp);
        // 等待子进程结束
        wait(NULL);
    }

    return 1;
}

int masscan_output_format(PGconn* conn, FILE* fp, Masscan_data* data, CacheManager* manager)
//TODO:需要把数据统计出然后送入数据库，但目前仅用输出至json文件做测试
{
    unsigned long count = 0;
    while (fgets(data->line_data, sizeof(data->line_data), fp) != NULL) {
        // 去除行尾换行符
        data->line_data[strcspn(data->line_data, "\n")] = 0;
        // 检查是否为开放端口输出（以 "Discovered open port" 开头）

        if (strncmp(data->line_data, "Discovered open", 15) == 0) {
            // 尝试解析格式为 "Discovered open port %d/%s on %s"
            if (sscanf(data->line_data, "Discovered open  %u %9s %15s", &data->port, data->protocol, data->ipv4) == 3) {
                // 成功解析，打印格式化输出
                //printf("No.%lu发现开放端口 - IP: %s, 端口: %d, 协议: %s\n", ++count, data->ipv4, data->port, data->protocol);
            }
            /*匹配banner扫描*/
        }
        if (strncmp(data->line_data, "Banner", 6) == 0) {
            if (sscanf(data->line_data, "Banner %u %9s %15s %127s %5119[^\n]", &data->port, data->protocol, data->ipv4, data->service, data->banner) == 5) {
                //printf("No.%lu 发现服务 - IP: %s, 端口: %d, 协议: %s, 服务: %s, Banner: %s\n", ++count, data->ipv4, data->port, data->protocol, data->service, data->banner);
                if (!write_to_database(conn, manager)) return 0;
                if (stop_signal) return 0;                        //收到停止信号，直接退出函数。（就目前为止，我认为 0 和 1 都可以）
            }
        }

    }
    return 1;
}

int check_masscan_config(MasscanConfig* masscan_config)
{
    if (!masscan_config->target_ip || !masscan_config->target_port || !masscan_config->masscan_path || !masscan_config->banner_scan_ip || !masscan_config->rate)
    {
        return 0;
    }
    return 1;
}

int free_masscan_config(MasscanConfig* masscan_config)
{
    if (!masscan_config->target_ip) free(masscan_config->target_ip);
    if (!masscan_config->target_port) free(masscan_config->target_port);
    if (!masscan_config->masscan_path) free(masscan_config->masscan_path);
    if (!masscan_config->banner_scan_ip) free(masscan_config->banner_scan_ip);
    if (!masscan_config->rate) free(masscan_config->rate);
    return 1;
}

