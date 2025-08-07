
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <postgresql/libpq-fe.h>
#include <signal.h>

#include "masscan_main.h"
#include "db-postgresql.h"
#include "http_conn.h"
#include "cJSON.h"

//#include "uthash.h" //哈希表库
int stop_signal = 0;

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

int check_write(const CacheManager* manager)
{
    if (!manager) return 0;
    if (stop_signal == 1) return 1; //更改写入数据库逻辑，仅在收到停止信号或结束扫描时写入，没有写入条数限制

    return 0;
}

/**
* 发送目标相关信息
*/
int send_target(int write_fd, const char* target)
{
    size_t len = strlen(target);
    if (write(write_fd, &len, sizeof(size_t)) != sizeof(size_t)) return 0;
    if (write(write_fd, target, len) != (ssize_t)len) return 0;
    return 1;
    
}

/**
* 接收目标相关信息
*/
char* receive_target(int read_fd)
{
    size_t len;
    if (read(read_fd, &len, sizeof(size_t)) != sizeof(size_t)) return NULL;

    char* receive_content = malloc(len + 1);
    if (read(read_fd, receive_content, len) != (ssize_t)len)
    {
        free(receive_content);
        return NULL;
    }

    receive_content[len] = '\0';
    return receive_content;
}

/**
* 用于子进程发送完成信号
*/
int send_completion_signal(int write_fd) {
    const char* signal = "COMPLETE";
    size_t len = strlen(signal);
    if (write(write_fd, &len, sizeof(size_t)) != sizeof(size_t)) return 0;
    if (write(write_fd, signal, len) != (ssize_t)len) return 0;
    return 1;
}

/**
* 用于父进程检查完成信号
*/
int check_completion_signal(int read_fd) {
    size_t len;
    if (read(read_fd, &len, sizeof(size_t)) != sizeof(size_t)) return 0;

    char* signal = malloc(len + 1);
    if (!signal) return 0;

    ssize_t bytes_read = read(read_fd, signal, len);
    if (bytes_read != (ssize_t)len) {
        free(signal);
        return 0;
    }

    signal[len] = '\0';
    int result = (strcmp(signal, "COMPLETE") == 0);   //如果是完成信号则返回1
    free(signal);
    return result;
}



int main(int argc, char* argv[]) {
    if (argc != 6)
    {
        printf("参数不足，只有%d\n", argc);
    }
	setbuf(stdout, NULL); // 禁用缓冲，确保输出立即显示
    if (!sign_signal_func()) return 0;                    //注册信号处理函数
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
    printf("开始初始数据库\n");
    if (!postgresql_init(conn))
    {
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    }

    ScanData* data = malloc(sizeof(ScanData));
    if (!data)
    {
		fprintf(stderr, "Masscan data内存分配失败\n");
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    } 
    printf("分配scan data成功\n");
	ScanConfig* scan_config = malloc(sizeof(ScanConfig));

    if (!scan_config)
    {
        free(data);
        PQfinish(conn);
        clear_cache_manager(manager);
        exit(1);
    }
    printf("分配scan config成功\n");

    scan_config->target_ip = strdup(argv[1]);
    scan_config->target_port = strdup(argv[2]);
    scan_config->scanner_path = strdup(argv[5]);
    scan_config->banner_scan_ip = strdup(argv[4]);
    scan_config->rate = strdup(argv[3]);

    if (!check_scan_config)
    {
        free_scan_config(scan_config);
        free(data);
        PQfinish(conn);
        clear_cache_manager(manager);
        exit(1);
    }
    
    if (!stop_signal)
    {
        scan(conn, data, manager, scan_config);
        printf("扫描完成\n");
    }
    

    /**
    * 清理分配的内存
    */
    free(data);
    PQfinish(conn);
    clear_cache_manager(manager);
    free_scan_config(scan_config);
    printf("垃圾清理完毕\n");

    return 0;
}

/*
先创建一个子线程，然后在子线程中执行扫描
*/
int scan(PGconn* conn, ScanData* ScanData, CacheManager* manager, ScanConfig* scan_config)
{/// XXX:需要能够接受ipv6并处理
    pid_t pid;              // 进程ID

    int parent_to_child[2];      //父进程写入操作，子进程读取
    int child_to_parent[2];      //子进程写入操作，父进程读取

    //开始创建管道
    if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1)
    {
        perror("创建管道失败");
        return 0;
    }

    // 创建子进程
    pid = fork();
    if (pid == -1) {
        perror("创建子进程失败");
        //exit(EXIT_FAILURE);
        return 0;
    }

    if (pid == 0) { // 子进程
        // 关闭管道读端
        close(parent_to_child[1]); //关闭写入
        close(child_to_parent[0]); //关闭读取
        // 将标准输出重定向到管道写端
        dup2(child_to_parent[1], STDOUT_FILENO);
        // 将标准错误输出也重定向到管道（捕获所有输出）
        dup2(child_to_parent[1], STDERR_FILENO);
        
        while (!stop_signal)
        {
            char* target = receive_target(parent_to_child[0]);
            if (!target) return 0;
            if (!strcmp(target, "DONE"))   //子进程扫描结束和主进程发送完毕指令使用不同标识符以区分
            {
                stop_signal = 1;
                break;
            }

            if (execlp("./a", 
                "a", 
                "-p80,22,53,8000,7601", 
                scan_config->target_ip, 
                "--rate=10000", 
                "--banner", 
                "--source-ip", 
                scan_config->banner_scan_ip, 
                NULL) == -1
                )
            {
                perror("执行错误");
                free(target);
                close(child_to_parent[1]);
                return 0;
            }
            printf("COMPLETE\n");
            free(target);
        }

        close(child_to_parent[1]);


    }
    else { // 父进程
        // 关闭管道写端
        close(parent_to_child[0]);         //关闭读取，用于向子进程发送目标
        close(child_to_parent[1]);         //关闭写入，用于接收子进程发送到数据
        // 将管道读端转换为 FILE* 流
        FILE* fp = fdopen(child_to_parent[0], "r");
        if (fp == NULL) {
            perror("转换管道为流失败");
            exit(EXIT_FAILURE);
        }

        while (!stop_signal)
        {

            /*稍后添加获取目标的代码*/
            char* result = http_requests("http;//127.0.0.1/scanner/target");
            if (!result)
            {
                sleep(5);
                free(result);
                continue;
            }
            cJSON* root = cJSON_Parse(result);

            if (!scan_output_format(conn, fp, ScanData, manager, scan_config, "masscan"))
            {
                clear_cache_data(manager);
                fclose(fp);
                wait(NULL); // 等待子进程结束
                return 0;
            }
            free(result);

        }

        clear_cache_data(manager);
        // 清理
        fclose(fp);
        // 等待子进程结束
        wait(NULL);
    }

    return 1;
}

int scan_output_format(PGconn* conn, FILE* fp, ScanData* data, CacheManager* manager, ScanConfig* scan_config, const char* scanner_name)
//TODO:需要把数据统计出然后送入数据库，但目前仅用输出至json文件做测试
{
    //unsigned long count = 0;
    while (fgets(data->line_data, sizeof(data->line_data), fp) != NULL) {
        // 去除行尾换行符
        data->line_data[strcspn(data->line_data, "\n")] = 0;

        if (!strncmp(data->line_data, "Banner", 6)) {
            if (sscanf(data->line_data, "Banner %u %9s %15s %127s %5119[^\n]", &data->port, data->protocol, data->ipv4, data->service, data->banner) == 5) {
                //printf("No.%lu 发现服务 - IP: %s, 端口: %d, 协议: %s, 服务: %s, Banner: %s\n", ++count, data->ipv4, data->port, data->protocol, data->service, data->banner);
                //printf("IP: %s\n", data->ipv4);
                if (stop_signal) return 0;                        //收到停止信号，直接退出函数。（就目前为止，我认为 0 和 1 都可以）
                
                if (check_write(manager))
                {
                    if (!write_to_database(conn, manager)) return 0;
                }
                else
                {
                    if (!add_scan_result_to_cache(manager, data->ipv4, scanner_name, data->port, data->service, data->protocol, data->banner)) return 0;
                }
            }
        }
        else if (!strncmp(data->line_data, "COMPLETE", 8))
        {
            break;
        }
        else if (!strncmp(data->line_data, "ERROR", 5))
        {
            stop_signal = 1;
            break;
        }

    }
    if (!write_to_database(conn, manager)) return 0;
    return 1;
}

int check_scan_config(ScanConfig* scan_config)
{
    if (!scan_config->target_ip || !scan_config->target_port || !scan_config->scanner_path || !scan_config->banner_scan_ip || !scan_config->rate)
    {
        return 0;
    }
    return 1;
}

int free_scan_config(ScanConfig* scan_config)
{
    if (scan_config->target_ip) free(scan_config->target_ip);
    if (scan_config->target_port) free(scan_config->target_port);
    if (scan_config->scanner_path) free(scan_config->scanner_path);
    if (scan_config->banner_scan_ip) free(scan_config->banner_scan_ip);
    if (scan_config->rate) free(scan_config->rate);
    return 1;
}

