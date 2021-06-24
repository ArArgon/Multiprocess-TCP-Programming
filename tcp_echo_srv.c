/*
	实验4-套接字编程-TCP多进程并发服务器与多进程客户端参考模版——服务器端
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdbool.h>

// #define DEBUG

#ifdef DEBUG
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
char *base64_encode(const unsigned char *, size_t, size_t *);
unsigned char *base64_decode(const char *, size_t, size_t *);
void build_decoding_table();
void base64_cleanup();

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                          + (sextet_b << 2 * 6)
                          + (sextet_c << 1 * 6)
                          + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}

#define print_base(pos) {                                           \
    char* tmp = NULL;                                               \
    size_t tmp_len;                                                 \
    tmp = base64_encode((char *)buf + (pos), res, &tmp_len);        \
    say(stderr, "Data: %s", tmp);                                   \
    free(tmp);                                                      \
}
#endif

#define BACKLOG     1024
#define MAX_BUFF    1024

#define bprintf(fp, format, ...)                        \
	if(fp == NULL) {                                    \
	    printf(format, ##__VA_ARGS__);                  \
	} else {                                            \
	    printf(format, ##__VA_ARGS__);                  \
		fprintf(fp, format, ##__VA_ARGS__);fflush(fp);  \
	}	// 后面的输出到文件操作，建议使用这个宏，还可同时在屏幕上显示出来

#define say(fp, format, ...) {                      \
    char _buff[MAX_BUFF], _buff2[MAX_BUFF];         \
    sprintf(_buff, format, __VA_ARGS__);            \
    sprintf(_buff2, "[srv](%d) %s\n", pid, _buff);  \
    bprintf(fp, "%s", _buff2);                      \
}

int sig_type = 0, sig_to_exit = 0;
FILE * fp_res = NULL;	//文件指针

void sig_int(int signo) {
    // TODO 记录本次系统信号编号到sig_type中;通过getpid()获取进程ID，按照指导书上的要求打印相关信息，并设置sig_to_exit的值
    pid_t pid = getpid();
    sig_to_exit = sig_type = signo;
#ifdef DEBUG
    say(stderr, "Signal: %d", signo);
#endif
    say(fp_res, "%s is coming!", "SIGINT");
}
void sig_pipe(int signo) {
    // TODO 记录本次系统信号编号到sig_type中;通过getpid()获取进程ID，按照指导书上的要求打印相关信息，并设置sig_to_exit的值
    pid_t pid = getpid();
    sig_to_exit = sig_type = signo;
#ifdef DEBUG
    say(stderr, "Signal: %d", signo);
#endif
    say(fp_res, "%s is coming!", "SIGPIPE");
}

void sig_chld(int signo) {
    pid_t pid = getpid(), pid_chld;
    int stat;
    say(fp_res, "%s is coming!", "SIGCHLD");
#ifdef DEBUG
    say(stderr, "Signal: %d", signo);
#endif
    while ((pid_chld = waitpid(-1, &stat, WNOHANG)) > 0) {
        say(fp_res, "server child(%d) terminated.", pid_chld);
#ifdef DEBUG
        say(stderr, "Child returns %d.", WEXITSTATUS(stat));
#endif
        return;
    }
}


/*
int install_sig_handlers()
功能：安装SIGPIPE,SIGCHLD,SIGINT三个信号的处理函数
	返回值：
		-1，安装SIGPIPE失败；
		-2，安装SIGCHLD失败；
		-3，安装SIGINT失败；
		 0，都成功
*/
int install_sig_handlers() {
    int res;
    struct sigaction sigact_pipe, old_sigact_pipe;
    sigact_pipe.sa_handler = sig_pipe;//sig_pipe()，信号处理函数
    // sigact_pipe.sa_flags = SA_RESTART;//设置受影响的慢系统调用重启
    sigemptyset(&sigact_pipe.sa_mask);
    res = sigaction(SIGPIPE, &sigact_pipe, &old_sigact_pipe);
    if (res)
        return -1;

    // TODO 安装SIGCHLD信号处理器,若失败返回-2.这里可直接将handler设为SIG_IGN，忽略SIGCHLD信号即可，
    // 注意和上述SIGPIPE一样，也要设置受影响的慢系统调用重启。也可以按指导书说明用一个自定义的sig_chld
    // 函数来处理SIGCHLD信号(复杂些)
    struct sigaction sigact_chld = {
            .sa_handler = sig_chld,
            .sa_flags = SA_RESTART,
    }, sigact_chld_old;
    sigemptyset(&sigact_chld.sa_mask);
    res = sigaction(SIGCHLD, &sigact_chld, &sigact_chld_old);
    if (res)
        return -2;

    // TODO 安装SIGINT信号处理器,若失败返回-3
    struct sigaction sigact_int = {
            .sa_handler = sig_int, // ignore
            .sa_flags = 0
    }, sigact_int_old;
    sigemptyset(&sigact_int.sa_mask);
    res = sigaction(SIGINT, &sigact_int, &sigact_int_old);
    if (res)
        return -3;

    return 0;
}

/*
int echo_rep(int sockfd)
功能：业务处理函数
	返回：
		-1，未获取客户端PIN
		>1，有效的客户端PIN
*/
int echo_rep(int sockfd) {
    int len_h = -1, len_n = -1;    //h后缀的用来存放主机字节序的结果，n的用来存放网络上读入的网络字节序结果，下同
    int pin_h = -1, pin_n = -1;
    int res;
    char buf[MAX_BUFF];
    pid_t pid = getpid();
#ifdef DEBUG
    say(stderr, "Entering the child(%d)...", pid);
#endif
    // 读取客户端PDU并执行echo回复
    do {
#ifdef DEBUG
        say(stderr, "Entering %s loop", "echo_rep");
#endif
        // 读取客户端PIN（Process Index， 0-最大并发数），并创建记录文件
        // buf = (char *) malloc(8);
        memset(buf, 0, sizeof buf);
        while (true) {
#ifdef DEBUG
            say(stderr, "Waiting for %s sending data", "client");
#endif
            //TODO 用read读取PIN（网络字节序）到pin_n中；返回值赋给res
            res = read(sockfd, buf, 4);
#ifdef DEBUG
            say(stderr, "receiving pin data(%d)", 1);
#endif
            if (res < 0) {
                bprintf(fp_res, "[srv](%d) read pin_n return %d and errno is %d!\n", pid, res, errno);
#ifdef DEBUG
                say(stderr, "Hint: %s", strerror(errno));
#endif
                if (errno == EINTR) {
                    if (sig_type == SIGINT)
                        return pin_h;
                    continue;
                }
                return pin_h;
            }
            if (!res)
                return pin_h;
            // TODO 将pin_n字节序转换后存放到pin_h中
#ifdef DEBUG
            say(stderr, "Received data, size: %d", res);
            print_base(0);
#endif
            memcpy(&pin_n, buf, 4);
            pin_h = ntohl(pin_n);
#ifdef DEBUG
            say(stderr, "PIN: %d", pin_h);
#endif
            break;
        }

        // 读取客户端echo_rqt数据长度
        while (true) {
            // TODO 用read读取客户端echo_rqt数据长度（网络字节序）到len_n中:返回值赋给res
            res = read(sockfd, buf + 4, 4);
#ifdef DEBUG
            say(stderr, "receiving data(%d)", 2);
#endif
            if (res < 0) {
                bprintf(fp_res, "[srv](%d) read len_n return %d and errno is %d\n", pid, res, errno);
                if (errno == EINTR) {
                    if (sig_type == SIGINT)
                        return len_h;
                    continue;
                }
                return len_h;
            }
            if (!res)
                return len_h;
            // TODO 将len_n字节序转换后存放到len_h中
#ifdef DEBUG
            say(stderr, "Received data, size: %d", res);
            print_base(4);
#endif
            memcpy(&len_n, buf + 4, 4);
            len_h = ntohl(len_n);
#ifdef DEBUG
            say(stderr, "Expected data length: %d", len_h);
#endif
            break;
        }

        // 读取客户端echo_rqt数据
        // free(buf);
        // 预留PID与数据长度的存储空间，为后续回传做准备
        // buf = realloc(buf, PDU_BUFF * sizeof(char));
        // buf = (char *) malloc(PDU_BUFF * sizeof(char));
        // TODO 客户端数据可能一次read不完，要多次读取，因此要定义一个变量read_amnt来存放每次已累计读取的字节数，
        // 以及另一个变量len_to_read来存放每次还需要读取多少数据（等于len_h减去read_amnt），read函数的参数2和参数3
        // 的设定需要用到这两个变量
        int read_amnt = 0, len_to_read = len_h;
        char *pos = buf + 8;

        do {
            //TODO 使用read读取客户端数据，返回值赋给res。注意read第2、3个参数，即每次存放的缓冲区的首地址及所需读取的长度如何设定
#ifdef DEBUG
            say(stderr, "receiving data(%d), expected length: %d", 3, len_h);
#endif
            res = read(sockfd, pos + read_amnt, len_to_read);
#ifdef DEBUG
            say(stderr, "Received bytes: %d", len_h);
            print_base(8 + read_amnt);
#endif
            if (res < 0) {
                bprintf(fp_res, "[srv](%d) read data return %d and errno is %d,\n", pid, res, errno);
                if (errno == EINTR) {
                    if (sig_type == SIGINT) {
                        // free(buf);
                        return pin_h;
                    }
                    continue;
                }
                // free(buf);
                return pin_h;
            }
            if (!res) {
                // free(buf);
                return pin_h;
            }

            //TODO 此处计算read_amnt及len_to_read的值，注意考虑已读完和未读完两种情况，以及其它情况（此时直接用上面的代码操作，free(buf),并 return pin_h）
            len_to_read -= res, read_amnt += res;

            if (len_to_read < 0 || len_to_read + read_amnt != len_h) {
                // free(buf);
                return pin_h;
            }
            if (!len_to_read)
                break;
        } while (true);
#ifdef DEBUG
        say(stderr, "Writing data to file %s", "");
#endif
        //TODO 解析客户端echo_rqt数据并写入res文件；注意缓冲区起始位置哦
        fprintf(fp_res, "[echo_rqt](%d) %s\n", pid, buf + 8);

        // 将客户端PIN写入PDU缓存（网络字节序）
        memcpy(buf, &pin_n, 4);
        // 将echo_rep数据长度写入PDU缓存（网络字节序）
        memcpy(buf + 4, &len_n, 4);

        //TODO 用write发送echo_rep数据并释放buf:
#ifdef DEBUG
        say(stderr, "Sending data to %s, length: %d", "client", len_h + 8);
#endif
        if (write(sockfd, buf, 8 + len_h) < 0) {
            // error
            say(stderr, "Sending data failed: %s", strerror(errno));
            // free(buf);
            break;
        }
        // free(buf);
#ifdef DEBUG
        say(stderr, "Sending %s", "complete.");
#endif
    } while (1);
    return pin_h;
}

int main(int argc, char* argv[]) {
    // 基于argc简单判断命令行指令输入是否正确；
    if (argc != 3) {
        printf("Usage:%s <IP> <PORT>\n", argv[0]);
        return -1;
    }

    // 获取当前进程PID，用于后续父进程信息打印；
    pid_t pid = getpid();
    // 定义IP地址字符串（点分十进制）缓存，用于后续IP地址转换；
    char ip_str[20] = { 0 };//用于IP地址转换
    // 定义res文件名称缓存，用于后续文档名称构建；
    char fn_res[50] = { 0 };//
    // 定义结果变量，用于承接后续系统调用返回结果；
    int res;
    // TODO 调用install_sig_handlers函数，安装信号处理器，包括SIGPIPE，SIGCHLD以及SIGINT；如果返回的不是0，就打印一个出错信息然后返回res值
    if ((res = install_sig_handlers())) {
        printf("[srv](%d) unable to register signal handlers\n", getpid());
        return res;
    }

    // TODO 打开文件"stu_srv_res_p.txt"，用于后续父进程信息记录；
    fp_res = fopen("stu_srv_res_p.txt", "wb");
    if (!fp_res) {
        printf("[srv](%d) failed to open file \"stu_srv_res_p.txt\"!\n", pid);
        return res;
    }

    //TODO 定义如下变量：
    // 客户端Socket地址长度cli_addr_len（类型为socklen_t）；
    socklen_t cli_addr_len;
    // Socket监听描述符listenfd，以及Socket连接描述符connfd；
    int listenfd, connfd, port = atoi(argv[2]);


    // 服务器Socket地址srv_addr，客户端Socket地址cli_addr；
    //TODO 初始化服务器Socket地址srv_addr，其中会用到argv[1]、argv[2]
    /* IP地址转换推荐使用inet_pton()；端口地址转换推荐使用atoi(); */
    struct sockaddr_in srv_addr = {
            .sin_port = htons((short) port),
            .sin_zero = { 0 },
            .sin_family = AF_INET
    }, cli_addr;
    memset(&cli_addr, 0, sizeof cli_addr);
    if (inet_pton(AF_INET, argv[1], &srv_addr.sin_addr) < 0) {
        printf("[srv](%d) unable to write address into 'srv_addr'", getpid());
        exit(-1);
    }

    //TODO 按题设要求打印服务器端地址server[ip:port]到fp_res文件中，推荐使用inet_ntop();
    if (inet_ntop(AF_INET, &srv_addr.sin_addr, ip_str, sizeof(ip_str)) < 0) {
        printf("[srv](%d) unable to write address into 'ip_buff'", getpid());
        exit(-1);
    }
    say(fp_res, "server[%s:%d] is initializing!", ip_str, port);


    //TODO 获取Socket监听描述符: listenfd = socket(x,x,x);
    listenfd = socket(AF_INET, SOCK_STREAM, 0);


    //TODO 绑定服务器Socket地址: res = bind(x,x,x);
    res = bind(listenfd, (struct sockaddr *) &srv_addr, sizeof srv_addr);
    if (res < 0) {
        // error
        printf("[srv](%d) failed to bind socket!\n", pid);
        return res;
    }

    // TODO 开启服务监听: res = listen(x,x);
    res = listen(listenfd, BACKLOG);
    if (res < 0) {
        printf("[srv](%d) failed to listen!\n", pid);
        return res;
    }

    // 开启accpet()主循环，直至sig_to_exit指示服务器退出；
    while (!sig_to_exit) {
        short cli_port;
        //TODO 获取cli_addr长度，执行accept()：connfd = accept(x,x,x);
        connfd = accept(listenfd, (struct sockaddr *) &cli_addr, &cli_addr_len);


        // 以下代码紧跟accept()，用于判断accpet()是否因SIG_INT信号退出（本案例中只关心SIGINT）；也可以不做此判断，直接执行 connfd<0 时continue，因为此时sig_to_exit已经指明需要退出accept()主循环，两种方式二选一即可。
        if (connfd == -1 && errno == EINTR) {
            if (sig_type == SIGINT)
                break;
            continue;
        }

        //TODO 按题设要求打印客户端端地址client[ip:port]到fp_res文件中，推荐使用inet_ntop();
        cli_port = ntohs(cli_addr.sin_port);
        if (!inet_ntop(AF_INET, &cli_addr.sin_addr, ip_str, sizeof ip_str)) {
            fprintf(stderr, "[srv](%d) Unable to translate network address to string!", pid);
            return -1;
        }
        say(fp_res, "client[%s:%d] is accepted!", ip_str, cli_port);


        // 派生子进程对接客户端开展业务交互
        if (!fork()) { // 子进程
            // 获取当前子进程PID,用于后续子进程信息打印
            pid = getpid();
#ifdef DEBUG
            say(stderr, "Now child(%d) is running!\n", pid);
#endif
            // 打开res文件，首先基于PID命名，随后在子进程退出前再根据echo_rep()返回的PIN值对文件更名；
            sprintf(fn_res, "stu_srv_res_%d.txt", pid);
#ifdef DEBUG
            say(stderr, "Try opening file %s", fn_res);
#endif
            fp_res = fopen(fn_res, "wb");// Write only， append at the tail. Open or create a binary file;
            if (!fp_res) {
                printf("[srv](%d) child exits, failed to open file \"stu_srv_res_%d.txt\"!\n", pid, pid);
                exit(-1);
            }
            //TODO 按指导书要求，将文件被打开的提示信息打印到stdout
            say(stdout, "stu_srv_res_%d.txt is opened!", pid);
            say(fp_res, "%s process is created!", "child");

            //TODO 关闭监听描述符，打印提示信息到文件中 ?
            close(listenfd);
            say(fp_res, "%s is closed!", "listenfd");


            //TODO 执行业务函数echo_rep（返回客户端PIN到变量pin中，以便用于后面的更名操作）
#ifdef DEBUG
            say(stderr, "Entering %s", "echo_rep");
#endif
            int pin = echo_rep(connfd);
#ifdef DEBUG
            fprintf(stderr, "Returned pin: %d\n", pin);
#endif
            if (pin < 0) {
                bprintf(fp_res, "[srv](%d) child exits, client PIN returned by echo_rqt() error!\n", pid);
                exit(-1);
            }
            // 更名子进程res文件（PIN替换PID）
            char fn_res_n[20] = { 0 };
            sprintf(fn_res_n, "stu_srv_res_%d.txt", pin);
            if (!rename(fn_res, fn_res_n)) {
                bprintf(fp_res, "[srv](%d) res file rename done!\n", pid);
            } else {
                bprintf(fp_res, "[srv](%d) child exits, res file rename failed!\n", pid);
            }

            //TODO 关闭连接描述符，输出信息到res文件中
            close(connfd);
            say(fp_res, "%s is closed!", "connfd");


            //TODO 关闭子进程res文件,并按指导书要求打印提示信息到stdout,然后exit
            say(fp_res, "%s process is going to exit!", "child");
            fclose(fp_res);
            say(NULL, "%s is closed!", fn_res);
            exit(0);
        } else {// 父进程
            //TODO 关闭连接描述符
            close(connfd);
        }
    }

    //TODO 关闭监听描述符
    close(listenfd);

    bprintf(fp_res, "[srv](%d) listenfd is closed!\n", pid);
    bprintf(fp_res, "[srv](%d) parent process is going to exit!\n", pid);

    //TODO 关闭父进程res文件,并按指导书要求打印提示信息至stdout
    fclose(fp_res);
    say(NULL, "%s is closed!", "stu_srv_res_p.txt");

    return 0;
}