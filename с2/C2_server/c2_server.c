#include "config.h"
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
#include <time.h>

volatile sig_atomic_t running = 1;
int server_sock = -1;

typedef struct client {
    int sock;
    pthread_t thread;
    char addr[INET_ADDRSTRLEN];
    struct client *next;
} client_t;

client_t *client_list = NULL;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

void add_client(client_t *new_client) {
    pthread_mutex_lock(&client_mutex);
    new_client->next = client_list;
    client_list = new_client;
    pthread_mutex_unlock(&client_mutex);
}

void remove_client(client_t *client) {
    pthread_mutex_lock(&client_mutex);
    client_t **cur = &client_list;
    while (*cur) {
        if (*cur == client) {
            *cur = client->next;
            break;
        }
        cur = &((*cur)->next);
    }
    pthread_mutex_unlock(&client_mutex);
}

void broadcast_message(const char *msg, size_t len) {
    pthread_mutex_lock(&client_mutex);
    client_t *cur = client_list;
    while (cur) {
        if (send(cur->sock, msg, len, 0) < 0) {
            perror("send");
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&client_mutex);
}

void *client_handler(void *arg) {
    client_t *client = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_received;
    
    while (running) {
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(client->sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            time_t now = time(NULL);
            char timestr[26];
            ctime_r(&now, timestr);
            timestr[strcspn(timestr, "\n")] = '\0';
            printf("[%s] Message from %s: %s\n", timestr, client->addr, buffer);
        } else if (bytes_received == 0) {
            printf("Client %s disconnected.\n", client->addr);
            break;
        } else {
            perror("recv");
            break;
        }
    }
    close(client->sock);
    remove_client(client);
    free(client);
    return NULL;
}

void *listener_thread(void *arg) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    while (running) {
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (running)
                perror("accept");
            continue;
        }
        client_t *client = malloc(sizeof(client_t));
        if (!client) {
            perror("malloc");
            close(client_sock);
            continue;
        }
        client->sock = client_sock;
        inet_ntop(AF_INET, &(client_addr.sin_addr), client->addr, INET_ADDRSTRLEN);
        
        add_client(client);
        if (pthread_create(&client->thread, NULL, client_handler, client) != 0) {
            perror("pthread_create");
            close(client_sock);
            remove_client(client);
            free(client);
        } else {
            printf("New client connected: %s\n", client->addr);
        }
    }
    return NULL;
}

void *console_thread(void *arg) {
    char input_buffer[BUFFER_SIZE];
    while (running) {
        if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
            size_t len = strlen(input_buffer);
            if (len > 0 && input_buffer[len - 1] == '\n')
                input_buffer[len - 1] = '\0';
            broadcast_message(input_buffer, strlen(input_buffer));
        } else {
            break;
        }
    }
    return NULL;
}

void sigint_handler(int signum) {
    running = 0;
    if (server_sock != -1) {
        close(server_sock);
        server_sock = -1;
    }
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) {
            fprintf(stderr, "Invalid port number.\n");
            exit(EXIT_FAILURE);
        }
    }
    
    signal(SIGINT, sigint_handler);
    
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("listen");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    
    printf("C2 Server listening on port %d...\n", port);
    
    pthread_t listener_tid, console_tid;
    if (pthread_create(&listener_tid, NULL, listener_thread, NULL) != 0) {
        perror("pthread_create (listener)");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&console_tid, NULL, console_thread, NULL) != 0) {
        perror("pthread_create (console)");
        running = 0;
        pthread_join(listener_tid, NULL);
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    
    pthread_join(listener_tid, NULL);
    pthread_join(console_tid, NULL);
    
    pthread_mutex_lock(&client_mutex);
    client_t *cur = client_list;
    while (cur) {
        close(cur->sock);
        cur = cur->next;
    }
    pthread_mutex_unlock(&client_mutex);
    
    printf("C2 Server shutting down.\n");
    return 0;
}
