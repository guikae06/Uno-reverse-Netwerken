#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <curl/curl.h>

#define LUISTER_POORT 22
#define BUFFER_GROOTTE 1024
#define LOGBOEK_BESTAND "unoreverse_log.txt"
#define WHOIS_LOGBOEK "whois_log.txt"

// Callback voor CURL om data in een string te stoppen
size_t curl_schrijf_callback(void *gegevens, size_t grootte, size_t aantal, void *doel) {
    strncat((char *)doel, (char *)gegevens, grootte * aantal);
    return grootte * aantal;
}

// Log IP, ontvangen data, geolocatie en verzonden bytes
void schrijf_logboek(const char *ip_adres, const char *ontvangen_bericht, const char *geolocatie_info, int verzonden_bytes) {
    FILE *logboek = fopen(LOGBOEK_BESTAND, "a");
    if (!logboek) {
        perror("Kan logboek niet openen");
        return;
    }

    time_t nu = time(NULL);
    char *tijdstip = ctime(&nu);
    tijdstip[strcspn(tijdstip, "\n")] = 0; // verwijder newline

    fprintf(logboek, "[%s] IP: %s\n", tijdstip, ip_adres);
    fprintf(logboek, "Ontvangen gegevens: %s\n", ontvangen_bericht);
    fprintf(logboek, "Geolocatie: %s\n", geolocatie_info);
    fprintf(logboek, "Totaal bytes teruggestuurd: %d\n\n", verzonden_bytes);

    fflush(logboek);
    fclose(logboek);

    printf("Succesvol gelogd voor IP %s\n", ip_adres);
}

// Vraag geolocatie op via ip-api.com
void haal_geolocatie_op(const char *ip_adres, char *resultaat, size_t resultaat_grootte) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "CURL initialisatie mislukt\n");
        snprintf(resultaat, resultaat_grootte, "Geen geolocatie beschikbaar");
        return;
    }

    char url[256];
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", ip_adres);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_schrijf_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resultaat);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode status = curl_easy_perform(curl);
    if (status != CURLE_OK) {
        fprintf(stderr, "CURL fout: %s\n", curl_easy_strerror(status));
        snprintf(resultaat, resultaat_grootte, "Geolocatie fout");
    }

    curl_easy_cleanup(curl);
}

// Voer een WHOIS-opzoeking uit en log het resultaat
void log_whois_data_van_ip(const char *ip_adres) {
    char commando[256];
    char leesbuffer[4096];
    FILE *whois_output;
    FILE *logboek = fopen(WHOIS_LOGBOEK, "a");

    if (!logboek) {
        perror("Kan WHOIS logboek niet openen");
        return;
    }

    snprintf(commando, sizeof(commando), "whois %s", ip_adres);
    whois_output = popen(commando, "r");

    if (!whois_output) {
        fprintf(logboek, "WHOIS mislukt voor %s\n", ip_adres);
        fclose(logboek);
        return;
    }

    fprintf(logboek, "WHOIS voor IP: %s\n", ip_adres);
    while (fgets(leesbuffer, sizeof(leesbuffer), whois_output) != NULL) {
        fputs(leesbuffer, logboek);
    }
    fprintf(logboek, "\n-----------------------------------\n\n");

    fflush(logboek);
    pclose(whois_output);
    fclose(logboek);

    printf("WHOIS info gelogd voor IP %s\n", ip_adres);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_adres, client_adres;
    socklen_t client_adres_grootte = sizeof(client_adres);
    char ontvangen_buffer[BUFFER_GROOTTE];
    char client_ip[INET_ADDRSTRLEN];
    char geolocatie_resultaat[4096] = {0};
    char terugstuur_buffer[1024] = {0};
    int ontvangen_bytes;
    int totaal_verzonden_bytes;

    // Maak socket aan
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket aanmaken mislukt");
        exit(EXIT_FAILURE);
    }

    // Bind socket
    server_adres.sin_family = AF_INET;
    server_adres.sin_addr.s_addr = INADDR_ANY;
    server_adres.sin_port = htons(LUISTER_POORT);

    if (bind(server_socket, (struct sockaddr *)&server_adres, sizeof(server_adres)) < 0) {
        perror("Bind mislukt (poort 22 vereist rootrechten)");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0) {
        perror("Luisteren mislukt");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("UnoReverse server luistert op poort %d...\n", LUISTER_POORT);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_adres, &client_adres_grootte);
        if (client_socket < 0) {
            perror("Verbinding accepteren mislukt");
            continue;
        }

        inet_ntop(AF_INET, &client_adres.sin_addr, client_ip, sizeof(client_ip));
        printf("Nieuwe verbinding van %s\n", client_ip);

        // Lees inloggegevens of eerste bericht
        ontvangen_bytes = recv(client_socket, ontvangen_buffer, sizeof(ontvangen_buffer) - 1, 0);
        if (ontvangen_bytes <= 0) {
            close(client_socket);
            continue;
        }
        ontvangen_buffer[ontvangen_bytes] = '\0';
        printf("Ontvangen: %s\n", ontvangen_buffer);

        // Geolocatie opvragen
        memset(geolocatie_resultaat, 0, sizeof(geolocatie_resultaat));
        haal_geolocatie_op(client_ip, geolocatie_resultaat, sizeof(geolocatie_resultaat));

        // WHOIS data loggen
        log_whois_data_van_ip(client_ip);

        // Reverse attack: stuur oneindig data totdat client verbreekt
        totaal_verzonden_bytes = 0;
        while (1) {
            int verzonden = send(client_socket, terugstuur_buffer, sizeof(terugstuur_buffer), 0);
            if (verzonden <= 0) {
                break;
            }
            totaal_verzonden_bytes += verzonden;
        }

        // Log alles
        schrijf_logboek(client_ip, ontvangen_buffer, geolocatie_resultaat, totaal_verzonden_bytes);

        close(client_socket);
    }

    close(server_socket);
    return 0;
}
