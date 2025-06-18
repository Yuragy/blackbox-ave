#include "config.h"
#include "sql_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

volatile sig_atomic_t running = 1;
int sockfd = -1;

void sigint_handler(int signum) {
    running = 0;
    if (sockfd != -1)
        close(sockfd);
}

void *server_listener(void *arg) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    while (running) {
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            printf("Received: %s\n", buffer);
            if (sql_manager_log_event(buffer) != SQLITE_OK) {
                fprintf(stderr, "SQL log failed for event: %s\n", buffer);
            }
        } else if (bytes_received == 0) {
            printf("Server disconnected.\n");
            running = 0;
            break;
        } else {
            perror("recv");
            running = 0;
            break;
        }
    }
    return NULL;
}

void *console_sender(void *arg) {
    char input_buffer[BUFFER_SIZE];
    while (running) {
        if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
            size_t len = strlen(input_buffer);
            if (len > 0 && input_buffer[len - 1] == '\n')
                input_buffer[len - 1] = '\0';
            if (send(sockfd, input_buffer, strlen(input_buffer), 0) < 0) {
                perror("send");
            }
            if (sql_manager_log_event(input_buffer) != SQLITE_OK) {
                fprintf(stderr, "SQL log failed for sent message: %s\n", input_buffer);
            }
        } else {
            break;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);
    char *server_ip = SERVER_IP;
    int port = SERVER_PORT;
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    if (sql_manager_init(DB_PATH) != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize SQL manager\n");
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        sql_manager_close();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address or address not supported\n");
        close(sockfd);
        sql_manager_close();
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        sql_manager_close();
        exit(EXIT_FAILURE);
    }

    {
        const char *beacon = "HELLO_FROM_CLIENT";
        if (send(sockfd, beacon, strlen(beacon), 0) < 0) {
            perror("send beacon");
        } else {
            sql_manager_log_event("Sent beacon: HELLO_FROM_CLIENT");
        }
    }

    pthread_t listener_tid, sender_tid;
    if (pthread_create(&listener_tid, NULL, server_listener, NULL) != 0) {
        perror("pthread_create (listener)");
        close(sockfd);
        sql_manager_close();
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&sender_tid, NULL, console_sender, NULL) != 0) {
        perror("pthread_create (sender)");
        running = 0;
        pthread_join(listener_tid, NULL);
        close(sockfd);
        sql_manager_close();
        exit(EXIT_FAILURE);
    }

    pthread_join(listener_tid, NULL);
    pthread_join(sender_tid, NULL);
    close(sockfd);
    sql_manager_close();
    return 0;
}
