#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>  // Nodig voor IP en sockets

#define SERVER_IP "127.0.0.1"   // Verander dit naar het IP van de server
#define SERVER_PORT 22          // Moet hetzelfde zijn als de serverpoort
#define BUFFER_SIZE 1024        // Grootte van het leesbuffer

int main() {
    int sock;                            // Socket file descriptor
    struct sockaddr_in server_address;  // Struct voor serverinfo
    char buffer[BUFFER_SIZE];           // Buffer voor ontvangen data
    int ontvangen_bytes;                // Aantal bytes ontvangen
    int totaal_ontvangen = 0;           // Totaal ontvangen bytes

    // 1. Maak een socket aan
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Kan geen socket maken");
        return 1;
    }

    // 2. Stel serveradres in
    server_address.sin_family = AF_INET;                       // IPv4
    server_address.sin_port = htons(SERVER_PORT);              // Poort instellen
    inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr);   // IP instellen

    // 3. Maak verbinding met de server
    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Verbinding met server mislukt");
        close(sock);
        return 1;
    }

    printf("Verbonden met server op %s\n", SERVER_IP);

    // 4. Verstuur nep inloggegevens
    const char *nep_login = "admin:Kaelig";
    send(sock, nep_login, strlen(nep_login), 0);
    printf("Inlogpoging verzonden: %s\n", nep_login);

    // 5. Ontvang gegevens van de server (reverse attack)
    while ((ontvangen_bytes = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        totaal_ontvangen += ontvangen_bytes;
    }

    // 6. Toon resultaat
    printf("Totaal ontvangen van server: %d bytes\n", totaal_ontvangen);

    // 7. Sluit socket
    close(sock);
    return 0;
}
