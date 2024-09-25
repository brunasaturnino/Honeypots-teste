#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>

#define SO_REUSEPORT 15  // Valor típico em muitos sistemas, mas pode variar

#define PORT 8080
#define LOG_FILE "honeypot_log.txt"

void log_attack(const char *ip_address, double duration, int repeat_count, const char *repeated_command) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Erro ao abrir o arquivo de log");
        exit(EXIT_FAILURE);
    }
    fprintf(log_file, "Ataque detectado do IP: %s, Duração total: %.2f segundos, Tentativas repetidas: %d, Comando repetido: %s\n", ip_address, duration, repeat_count, repeated_command);
    fclose(log_file);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char last_command[1024] = {0};
    int repeat_count = 0;
    char repeated_command[1024] = "Nenhum";

    // Criar socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Falha ao criar socket");
        exit(EXIT_FAILURE);
    }

    // Definir opções do socket
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Falha ao configurar opções do socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Vincular socket à porta
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Falha ao vincular socket");
        exit(EXIT_FAILURE);
    }

    // Escutar na porta especificada
    if (listen(server_fd, 3) < 0) {
        perror("Falha ao escutar na porta");
        exit(EXIT_FAILURE);
    }

    printf("Honeypot escutando na porta %d\n", PORT);

    while (1) {
        struct sockaddr_in attacker_addr;
        socklen_t attacker_addr_len = sizeof(attacker_addr);
        time_t start_time, end_time;

        // Aceitar uma conexão
        if ((new_socket = accept(server_fd, (struct sockaddr *)&attacker_addr, &attacker_addr_len)) < 0) {
            perror("Falha ao aceitar conexão");
            exit(EXIT_FAILURE);
        }

        // Capturar o horário de início do ataque
        start_time = time(NULL);

        // Receber dados (simular interação)
        while (1) {
            int bytes_read = recv(new_socket, buffer, 1024, 0);
            if (bytes_read <= 0) {
                // Se não há mais dados ou ocorreu um erro, sair do loop
                break;
            }
            buffer[bytes_read] = '\0'; // Certificar que a string está terminada
            
            // Comparar o comando atual com o comando anterior
            if (strcmp(buffer, last_command) == 0) {
                // Comando repetido
                repeat_count++;
                printf("Comando repetido detectado: %s\n", buffer);
                strncpy(repeated_command, buffer, 1024); // Atualizar o comando repetido
            } else {
                // Novo comando, atualizar o último comando
                strncpy(last_command, buffer, 1024);
            }
        }

        // Capturar o horário de término do ataque
        end_time = time(NULL);

        // Calcular a duração total da conexão
        double duration = difftime(end_time, start_time);

        // Registrar informações do ataque, incluindo o número de tentativas repetidas e o tempo total de conexão
        char *attacker_ip = inet_ntoa(attacker_addr.sin_addr);
        log_attack(attacker_ip, duration, repeat_count, repeated_command);

        // Fechar a conexão
        close(new_socket);
    }

    return 0;
}
