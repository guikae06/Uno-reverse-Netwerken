#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <curl/curl.h>
#include <pthread.h>

#define LUISTER_POORT 22
#define BUFFER_GROOTTE 1024
#define LOGBOEK_BESTAND "unoreverse_log.txt"
#define WHOIS_LOGBOEK "whois_log.txt"

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Linked list voor IP's
typedef struct IPNode {
    char ip[INET_ADDRSTRLEN];
    struct IPNode *volgende;
} IPNode;

IPNode *ip_lijst = NULL;

// Voeg IP toe aan linked list
void voeg_ip_toe(const char *ip) {
    IPNode *nieuw = malloc(sizeof(IPNode));
    if (!nieuw) return;
    strncpy(nieuw->ip, ip, sizeof(nieuw->ip));
    nieuw->volgende = ip_lijst;
    ip_lijst = nieuw;
}

// Callback voor CURL
size_t curl_schrijf_callback(void *gegevens, size_t grootte, size_t aantal, void *doel) {
    strncat((char *)doel, (char *)gegevens, grootte * aantal);
    return grootte * aantal;
}

// Geolocatie ophalen
void haal_geolocatie_op(const char *ip_adres, char *resultaat, size_t resultaat_grootte) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(resultaat, resultaat_grootte, "Geen geolocatie beschikbaar");
        return;
    }

    char url[256];
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", ip_adres);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_schrijf_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resultaat);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    if (curl_easy_perform(curl) != CURLE_OK) {
        snprintf(resultaat, resultaat_grootte, "Geolocatie fout");
    }

    curl_easy_cleanup(curl);
}

// WHOIS loggen
void log_whois_data_van_ip(const char *ip_adres) {
    char commando[256], buffer[4096];
    snprintf(commando, sizeof(commando), "whois %s", ip_adres);
    FILE *whois_output = popen(commando, "r");
    FILE *logboek = fopen(WHOIS_LOGBOEK, "a");

    if (!whois_output || !logboek) return;

    pthread_mutex_lock(&log_mutex);
    fprintf(logboek, "WHOIS voor IP: %s\n", ip_adres);
    while (fgets(buffer, sizeof(buffer), whois_output)) {
        fputs(buffer, logboek);
    }
    fprintf(logboek, "\n-------------------------------\n\n");
    fclose(logboek);
    pthread_mutex_unlock(&log_mutex);
    pclose(whois_output);
}

// Logboek bijwerken
void schrijf_logboek(const char *ip, const char *bericht, const char *geo, int verzonden) {
    FILE *logboek = fopen(LOGBOEK_BESTAND, "a");
    if (!logboek) return;

    time_t nu = time(NULL);
    char *tijd = ctime(&nu);
    tijd[strcspn(tijd, "\n")] = 0;

    pthread_mutex_lock(&log_mutex);
    fprintf(logboek, "[%s] IP: %s\n", tijd, ip);
    fprintf(logboek, "Ontvangen: %s\n", bericht);
    fprintf(logboek, "Geolocatie: %s\n", geo);
    fprintf(logboek, "Verzonden bytes: %d\n\n", verzonden);
    fclose(logboek);
    pthread_mutex_unlock(&log_mutex);
}

// Client-handler functie
void *verwerk_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr *)&client_addr, &len);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
    voeg_ip_toe(ip);

    char buffer[BUFFER_GROOTTE];
    char geo[4096] = {0};
    char dummy_data[1024] = {0};
    int bytes_ontvangen = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_ontvangen <= 0) {
        close(client_socket);
        return NULL;
    }
    buffer[bytes_ontvangen] = '\0';

    haal_geolocatie_op(ip, geo, sizeof(geo));
    log_whois_data_van_ip(ip);

    int totaal = 0;
    while (1) {
        int verzonden = send(client_socket, dummy_data, sizeof(dummy_data), 0);
        if (verzonden <= 0) break;
        totaal += verzonden;
    }

    schrijf_logboek(ip, buffer, geo, totaal);
    close(client_socket);
    return NULL;
}

int main() {
    int server_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    curl_global_init(CURL_GLOBAL_ALL);

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LUISTER_POORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind (poort 22 vereist root)");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("UnoReverse draait op poort %d\n", LUISTER_POORT);

    while (1) {
        int *nieuw_client_socket = malloc(sizeof(int));
        *nieuw_client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (*nieuw_client_socket < 0) {
            perror("Accept");
            free(nieuw_client_socket);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, verwerk_client, nieuw_client_socket);
        pthread_detach(tid); // We hoeven geen join
    }

    close(server_socket);
    curl_global_cleanup();
    return 0;
}
