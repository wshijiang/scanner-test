
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <postgresql/libpq-fe.h>
#include <signal.h>
#include <errno.h>
#include <spawn.h>

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

///**
//* 发送目标相关信息
//*/
//int send_target(int write_fd, const char* target)
//{
//    size_t len = strlen(target);
//    //if (write(write_fd, &len, sizeof(size_t)) != sizeof(size_t)) return 0;
//    if (write(write_fd, target, len) != (ssize_t)len) return 0;
//    return 1;
//    
//}
//
///**
//* 接收目标相关信息
//*/
//char* receive_target(int read_fd)
//{
//    //size_t len;
//    //if (read(read_fd, &len, sizeof(size_t)) != sizeof(size_t)) return NULL;
//
//    char* receive_content = malloc(1000);
//    if (read(read_fd, receive_content, len) == -1)
//    {
//        free(receive_content);
//        return NULL;
//    }
//
//    receive_content[999] = '\0';
//    return receive_content;
//}

/**
 * 发送目标或控制信号（纯文本行协议）
 */
int send_target(int write_fd, const char* target) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s\n", target);
    size_t len = strlen(buffer);
    if (write(write_fd, buffer, len) != (ssize_t)len) {
        perror("Failed to send target");
        return 0;
    }
    return 1;
}

/**
 * 接收目标或控制信号（纯文本行协议）
 */
char* receive_target(int read_fd) {
    static char buffer[256];
    static int buffer_pos = 0;
    static int buffer_len = 0;

    // 查找缓冲区中是否有完整的行
    for (int i = buffer_pos; i < buffer_len; i++) {
        if (buffer[i] == '\n') {
            // 找到完整的行
            int line_len = i - buffer_pos;
            char* result = malloc(line_len + 1);
            if (!result) return NULL;

            memcpy(result, buffer + buffer_pos, line_len);
            result[line_len] = '\0';

            // 更新缓冲区位置
            buffer_pos = i + 1;
            if (buffer_pos >= buffer_len) {
                buffer_pos = buffer_len = 0;
            }

            return result;
        }
    }

    // 没有找到完整的行，需要读取更多数据
    if (buffer_pos > 0) {
        // 移动剩余数据到缓冲区开头
        memmove(buffer, buffer + buffer_pos, buffer_len - buffer_pos);
        buffer_len -= buffer_pos;
        buffer_pos = 0;
    }

    // 读取更多数据
    ssize_t bytes_read = read(read_fd, buffer + buffer_len, sizeof(buffer) - buffer_len - 1);
    if (bytes_read <= 0) {
        return NULL;
    }

    buffer_len += bytes_read;
    buffer[buffer_len] = '\0';

    // 递归调用查找行
    return receive_target(read_fd);
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

    if (!check_scan_config(scan_config))
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



// 新增函数：直接从文件描述符读取而不是FILE*
int scan_output_format_fd(PGconn* conn, int fd, ScanData* data, CacheManager* manager, ScanConfig* scan_config, const char* scanner_name)
{
    char buffer[8192];
    static char line_buffer[8192];
    static int line_pos = 0;

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        return 1; // 没有数据可读，继续
    }

    buffer[bytes_read] = '\0';

    // 处理接收到的数据，按行分割
    for (int i = 0; i < bytes_read; i++) {
        if (buffer[i] == '\n') {
            line_buffer[line_pos] = '\0';

            // 处理完整的一行
            if (!strncmp(line_buffer, "Banner", 6)) {
                unsigned int port;
                char protocol[10], ipv4[16], service[128], banner[5120];
                if (sscanf(line_buffer, "Banner %u %9s %15s %127s %5119[^\n]", &port, protocol, ipv4, service, banner) == 5) {
                    if (stop_signal) return 0;

                    if (check_write(manager)) {
                        if (!write_to_database(conn, manager)) return 0;
                    }
                    else {
                        if (!add_scan_result_to_cache(manager, ipv4, scanner_name, port, service, protocol, banner)) return 0;
                    }
                }
            }
            else if (!strncmp(line_buffer, "COMPLETE", 8)) {
                printf("收到 COMPLETE\n");
                if (!write_to_database(conn, manager)) return 0;
                return 1;
            }
            else if (!strncmp(line_buffer, "ERROR", 5)) {
                printf("收到 ERROR\n");
                return 1;
            }

            line_pos = 0;
        }
        else {
            if (line_pos < sizeof(line_buffer) - 1) {
                line_buffer[line_pos++] = buffer[i];
            }
        }
    }

    return 1;
}

/*
先创建一个子线程，然后在子线程中执行扫描
*/
int scan(PGconn* conn, ScanData* ScanData, CacheManager* manager, ScanConfig* scan_config)
{
    pid_t pid;
    int parent_to_child[2];
    int child_to_parent[2];

    // 创建管道
    if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1) {
        perror("创建管道失败");
        return 0;
    }

    pid = fork();
    if (pid == -1) {
        perror("创建子进程失败");
        return 0;
    }

    if (pid == 0) { // 子进程
        close(parent_to_child[1]);
        close(child_to_parent[0]);

        // 重定向标准输出和错误输出
        dup2(child_to_parent[1], STDOUT_FILENO);
        dup2(child_to_parent[1], STDERR_FILENO);
        close(child_to_parent[1]);
        setbuf(stdout, NULL);

        while (!stop_signal) {
            char* target = receive_target(parent_to_child[0]);
            if (!target) {
                fprintf(stderr, "Failed to receive target: %s\n", strerror(errno));
                break;
            }

            if (!strcmp(target, "DONE")) {
                free(target);
                printf("COMPLETE\n");
                fflush(stdout);
                break;  // 跳出循环但不退出进程
            }

            // 执行扫描
            pid_t child_pid;
            posix_spawn_file_actions_t actions;
            posix_spawnattr_t attr;
            int status;

            if (posix_spawn_file_actions_init(&actions) != 0) {
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawnattr_init(&attr) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawnattr_setflags(&attr, 0) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                posix_spawnattr_destroy(&attr);
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDOUT_FILENO) != 0 ||
                posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDERR_FILENO) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                posix_spawnattr_destroy(&attr);
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            char* scan_argv[] = {
                "a",
                "-p80,22,53,8000,7601",
                target,
                "--rate=10000",
                "--banner",
                "--source-ip",
                (char*)scan_config->banner_scan_ip,
                NULL
            };

            status = posix_spawnp(&child_pid, "./a", &actions, &attr, scan_argv, NULL);

            // 清理资源
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);

            if (status != 0) {
                fprintf(stderr, "posix_spawnp failed: %s\n", strerror(status));
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            // 等待子子进程完成
            if (waitpid(child_pid, &status, 0) == -1) {
                printf("ERROR\n");
                fflush(stdout);
            }
            else {
                if (WIFEXITED(status)) {
                    printf("COMPLETE\n");
                    fflush(stdout);
                }
                else {
                    printf("ERROR\n");
                    fflush(stdout);
                }
            }

            free(target);
        }

        close(parent_to_child[0]);
        exit(0);

    }
    else { // 父进程
        close(parent_to_child[0]);
        close(child_to_parent[1]);

        // 不要对 child_to_parent[0] 使用 fdopen，直接读取
        int req_count = 0;
        const char* target_domain = "http://192.168.1.6:9999/scanner/target";

        while (!stop_signal) {
            // 检查子进程状态
            int status;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result > 0) {
                fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(status));
                break;
            }
            else if (result == -1) {
                perror("waitpid failed");
                break;
            }

            // 获取目标
            char* http_result = http_requests(target_domain);
            if (!http_result) {
                sleep(5);
                req_count++;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
                continue;
            }

            printf("获取目标成功\n");
            cJSON* root = cJSON_Parse(http_result);

            if (!root) {
                fprintf(stderr, "JSON parse failed\n");
                free(http_result);
                req_count++;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
                continue;
            }

            cJSON* ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
            if (cJSON_IsString(ip) && ip->valuestring != NULL) {
                if (!send_target(parent_to_child[1], ip->valuestring)) {
                    fprintf(stderr, "Failed to send target: %s\n", ip->valuestring);
                    cJSON_Delete(root);
                    free(http_result);
                    break;
                }
            }
            else {
                fprintf(stderr, "Invalid IP in JSON\n");
                req_count++;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
            }

            cJSON_Delete(root);
            free(http_result);

            // 处理扫描输出 - 修改为直接从文件描述符读取
            if (!scan_output_format_fd(conn, child_to_parent[0], ScanData, manager, scan_config, "masscan")) {
                printf("scan_output_format 失败，退出\n");
                clear_cache_data(manager);
                close(parent_to_child[1]);
                wait(NULL);
                return 0;
            }
        }

        if (req_count < 5 && !stop_signal) {
            send_target(parent_to_child[1], "DONE");
        }

        close(parent_to_child[1]);
        close(child_to_parent[0]);
        clear_cache_data(manager);
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
            printf("收到 COMPLETE\n");
            break;
        }
        else if (!strncmp(data->line_data, "ERROR", 5))
        {
            printf("收到 ERROR\n");
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

