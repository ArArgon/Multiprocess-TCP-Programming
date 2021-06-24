/*
 * Network Experiment 4
 *
 * Multiprocess client
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#define MAX_CMD_STR 100
#define MAX_BUFF    256
// #define DEBUG
#define bprintf(fp, format, ...) 			\
	if(fp == NULL || fp == stdout) {		\
		printf(format, ##__VA_ARGS__);		\
	} else {								\
		printf(format, ##__VA_ARGS__);		\
		fprintf(fp, format, ##__VA_ARGS__);	\
		fflush(fp); 						\
	}

#define say(fp, format, ...) {                      \
    char _buff[MAX_BUFF], _buff2[MAX_BUFF];         \
    sprintf(_buff, format, __VA_ARGS__);            \
    sprintf(_buff2, "[cli](%d) %s\n", pid, _buff);   \
    bprintf(fp, "%s", _buff2);                       \
}

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
    tmp = base64_encode((char *)buf + (pos), read_size, &tmp_len);  \
    say(stderr, "Data: %s", tmp);                                   \
    free(tmp);                                                      \
}
#endif

int sig_type = 0;
FILE * fp_res = NULL;//文件指针

void sig_pipe(int signo) {
    // TODO 记录本次系统信号编号到sig_type中;通过getpid()获取进程ID，按照指导书上的要求打印相关信息，并设置sig_to_exit的值
    pid_t pid = getpid();
    sig_type = signo;
    say(fp_res, "%s is coming", "SIGPIPE"); // wtf
}

/*
业务函数，构造PDU，发送到服务器端，并接收回送
*/

int echo_rqt(int sockfd, int pin)
{
    pid_t pid = getpid();
    // PDU定义：PIN LEN Data
    int len_h = 0, len_n = 0;   // len_h: native order, len_n: network order
    int pin_h = pin, pin_n = htonl(pin);
    char fn_td[10] = { 0 };
    char buf[MAX_CMD_STR + 1 + 8] = { 0 }; //定义应用层PDU缓存
    int res = 0;
#ifdef DEBUG
    say(stderr, "Process(%d): starts.", pid);
#endif
    // 读取测试数据文件
    sprintf(fn_td, "td%d.txt", pin);
    FILE * fp_td = fopen(fn_td, "r");
    if(!fp_td) {
        bprintf(fp_res, "[cli](%d) Test data read error!\n", pin_h);
        return 0;
    }

    // 读取一行测试数据，从编址 buf + 8 的字节开始写入，前8个字节分别留给 PIN 与数据长度 (均为int)
#ifdef DEBUG
    say(stderr, "Try reading from file %s", fn_td);
#endif
    while (fgets(buf + 8, MAX_CMD_STR, fp_td)) {
        // 重置pin_h & pin_n:
        pin_h = pin;
        pin_n = htonl(pin);
        // 指令解析:
        // 收到指令 "exit"，跳出循环并返回
        if(strncmp(buf + 8, "exit", 4) == 0) {
            // printf("[cli](%d) \"exit\" is found!\n", pin_h);
            break;
        }

        // 数据解析（构建应用层PDU）:
        // 将PIN写入PDU缓存（网络字节序）
        memcpy(buf, &pin_n, 4);
        // 获取数据长度
        len_h = strnlen(buf + 8, MAX_CMD_STR);
        // 将数据长度写入PDU缓存（网络字节序）
        len_n = htonl(len_h);
#ifdef DEBUG
        char* tmp = NULL;
        size_t tmp_len;
        tmp = base64_encode((uint8_t *) buf, len_h, &tmp_len);
        say(stderr, "Data read from file: %s", tmp);
        free(tmp);
#endif
        // write data length
        memcpy(buf + 4, &len_n, 4);
        // TODO 将读入的'\n'更换为'\0'；若仅有'\n'输入，则'\0'将被作为数据内容发出，数据长度为1

        bool only_ln = *(buf + 8) == '\n';
        for (char* buf_pos = buf + 8; buf_pos <= buf + 8 + len_h; buf_pos++) {
            only_ln &= *buf_pos == '\n';
            if (*buf_pos == '\n')
                *buf_pos = 0;
        }

        if (only_ln) {
            // set data length to 1 and fill the buffer with 0
            len_h = 1, len_n = htonl(1);
            memset(buf, 0, sizeof(buf));
            memcpy(buf, &pin_n, 4);
            memcpy(buf + 4, &len_n, 4);
        }
#ifdef DEBUG
        say(stderr, "Try sending data to server, pin: %d, len: %d", pin_h, len_h);
#endif
        // 用write发送echo_rqt数据
        if (write(sockfd, buf, len_h + 8) < 0) {
            // error
            say(stderr, "Sending data failed: %s", strerror(errno));
            return -1;
        }

        // 下面开始读取 echo_rep 返回来的数据，并存到res文件中
        // 此部分的功能代码，建议参考服务器端echo_rep中的代码来编写，此处不再重复
        // TODO 读取PIN（网络字节序）到pin_n中
        // TODO 读取服务器echo_rep数据长度（网络字节序）到len_n，并转为主机字节序存放到len_h
        // TODO 读取服务器echo_rep数据，并输出到res文件中
        memset(buf, 0, sizeof(buf));
        int read_aggr, recv_pin, recv_siz;
        // int first = 1;
#ifdef DEBUG
        say(stderr, "Now receiving pin from server, expected size: %d", 4);
#endif
        // read pin
        read_aggr = 0;
        int read_size = 0;
        while (true) {
            if ((read_size = read(sockfd, buf, 4)) < 0) {
                say(stderr, "Unable to read PIN, returns: %d", read_aggr);
                say(stderr, "Hint: %s", strerror(errno));
                return -1;
            }
            if ((read_aggr += read_size) < 4)
                continue;
            memcpy(&recv_pin, buf, 4);
            recv_pin = ntohl(recv_pin);
#ifdef DEBUG
            say(stderr, "Received bytes : %d", read_size);
            say(stderr, "Received PIN: %d", recv_pin);
            print_base(0);
#endif
            break;
        }
#ifdef DEBUG
        say(stderr, "Now receiving data size from server, expected size: %d", 4);
#endif
        // read size
        read_aggr = read_size = 0;
        while (true) {
            if ((read_size = read(sockfd, buf + 4, 4)) < 0) {
                say(stderr, "Unable to read length of data, returns: %d", read_aggr);
                say(stderr, "Hint: %s", strerror(errno));
                return -1;
            }
            if ((read_aggr += read_size) < 4)
                continue;
            memcpy(&recv_siz, buf + 4, 4);
            recv_siz = ntohl(recv_siz);
#ifdef DEBUG
            say(stderr, "Received bytes %d", read_size);
            say(stderr, "Received Size: %d", recv_siz);
            print_base(4);
#endif
            break;
        }
        // read data
#ifdef DEBUG
        say(stderr, "Now receiving data from server, expected size: %d", recv_siz);
#endif
        read_aggr = read_size = 0;
        while (true) {
            if ((read_size = read(sockfd, buf + 8 + read_aggr, len_h - read_aggr)) < 0) {
                say(stderr, "Unable to read data, returns: %d", read_aggr);
                say(stderr, "Hint: %s", strerror(errno));
                return -1;
            }
#ifdef DEBUG
            say(stderr, "Received %d bytes", read_size);
            print_base(8 + read_aggr);
#endif
            if ((read_aggr += read_size) >= len_h)
                break;
        }
        bprintf(fp_res, "[echo_rep](%d) %s\n", pid, buf + 8);
    }
    return 0;
}

int proc(int pin, struct sockaddr_in srv_addr, int srv_port, int pid) {
    int connfd;
    char fn_res[50];	// 用于处理文件名的字符数组

#ifdef DEBUG
    say(stderr, "Child(%d) launched.", pid);
#endif

    // TODO 获取当前子进程PID,用于后续子进程信息打印
    // ignored

    // 打开res文件，文件序号指定为当前子进程序号PIN；
#ifdef COMMAND_LINE_DEBUG
    fp_res = stdout;
#else
    sprintf(fn_res, "stu_cli_res_%d.txt", pin);
    fp_res = fopen(fn_res, "ab"); // Write only， append at the tail. Open or create a binary file;
#endif
    if(!fp_res) {
        printf("[cli](%d) child exits, failed to open file \"stu_cli_res_%d.txt\"!\n", pid, pin);
        exit(-1);
    }

    // TODO 将子进程已创建的信息打印到stdout（格式见指导书）
    if (pin)
        say(fp_res, "child process %d is created!", pin);

    // TODO 创建套接字connfd（注意加上出错控制）
    if (!(connfd = socket(AF_INET, SOCK_STREAM, 0))) {
        // error
        printf("[cli](%d) child exits, unable to create socket", pid);
        exit(-1);
    }
    while(true) {
#ifdef DEBUG
        say(stderr, "Connecting to server, port: %d", srv_port);
#endif
        int res;
        // 用connect连接到服务器端，返回值放在res里
        res = connect(connfd, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
        if(!res) {
            char ip_str[20] = { 0 };	//用于IP地址转换
            // TODO 将服务器端地址信息打印输出至对应的stu_cli_res_PIN.txt（见指导书）
            inet_ntop(AF_INET, &srv_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
            say(fp_res, "server[%s:%d] is connected!", ip_str, srv_port);

            if(!echo_rqt(connfd, pin))	//调用业务处理函数echo_rqt
                break;
        } else {
            fprintf(stderr, "[cli](%d) Unable to connect to server: %s\n", pid, strerror(errno));
            break;
        }
    }

    // 关闭连接描述符
    close(connfd);
    bprintf(fp_res, "[cli](%d) connfd is closed!\n", pid);

    // TODO 关闭子进程res文件，同时打印提示信息到stdout(格式见指导书)
    bprintf(fp_res, "[cli](%d) %s process is going to exit!\n", pid, pin ? "child" : "parent");
    fclose(fp_res);
    say(NULL, "%s is closed!", fn_res);
    exit(0);
    return 0;
}

int main(int argc, char* argv[]) {
    // 基于argc简单判断命令行指令输入是否正确；
    if(argc != 4) {
        printf("Usage:%s <IP> <PORT> <CONCURRENT AMOUNT>\n", argv[0]);
        return 0;
    }

    struct sigaction sigact_pipe, old_sigact_pipe;
    sigact_pipe.sa_handler = sig_pipe;//sig_pipe()，信号处理函数
    sigemptyset(&sigact_pipe.sa_mask);
    sigact_pipe.sa_flags = SA_RESTART;//设置受影响的慢系统调用重启
    sigaction(SIGPIPE, &sigact_pipe, &old_sigact_pipe);

    // TODO 安装SIGCHLD信号处理器.这里可直接将handler设为SIG_IGN，忽略SIGCHLD信号即可，
    // 注意和上述SIGPIPE一样，也要设置受影响的慢系统调用重启。也可以按指导书说明用一个自定义的sig_chld
    // 函数来处理SIGCHLD信号(复杂些)

    struct sigaction sigact_chld, sigact_chld_old;
    sigact_chld.sa_handler = SIG_IGN;	// ignore sigchild
    sigemptyset(&sigact_chld.sa_mask);
    sigact_chld.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sigact_chld, &sigact_chld_old);


    // TODO 定义如下变量：
    // 服务器 Socket 地址 srv_addr，客户端 Socket 地址 cli_addr;
    int srv_port = atoi(argv[2]);
    struct sockaddr_in srv_addr = {
            .sin_family = AF_INET,
            .sin_port = htons((short) srv_port),
            .sin_zero = { 0 }
    };
    if (inet_pton(AF_INET, argv[1], &srv_addr.sin_addr) <= 0) {
        // error
        printf("[cli](%d) unable to write address into 'srv_addr'", getpid());
        exit(-1);
    }

    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));

    // 客户端Socket地址长度cli_addr_len（类型为socklen_t）；
    socklen_t cli_addr_len = sizeof(cli_addr);
    // Socket连接描述符connfd；
    int connfd;

    // 最大并发连接数（含父进程）conc_amnt,其值由命令行第三个参数决定（用atoi函数）
    int conc_amnt = atoi(argv[3]);
    if (conc_amnt < 0) {
        // error
        fprintf(stderr, "Command invalid: concurrency amount should be positive");
        exit(-1);
    }
    // 获取当前进程PID，用于后续父进程信息打印；
    pid_t pid = getpid();

    //TODO 初始化服务器Socket地址srv_addr，其中会用到argv[1]、argv[2]
    /* IP地址转换推荐使用inet_pton()；端口地址转换推荐使用atoi(); */
    // [Done]

    /*
     * refactoring
     * */
#ifdef DEBUG
    fprintf(stderr, "Now starting ...\n");
#endif
    for (int i = 1; i <= conc_amnt - 1; i++)
        if (!fork())
            proc(i, srv_addr, srv_port, getpid());
    proc(0, srv_addr, srv_port, pid);
    return 0;
}