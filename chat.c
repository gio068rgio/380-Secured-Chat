#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "handshake.h"

#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <assert.h>
#include <openssl/x509.h>





#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 512
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkTextBuffer* mbuf;
static GtkTextView*  tview;
static GtkTextMark*   mark;

static pthread_t trecv;
void* recvMsg(void*);

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

static int listensock, sockfd;
static int isclient = 1;
#define KEY_SIZE 128
unsigned char sharedKey[KEY_SIZE];
static unsigned char sharedSecret[KEY_SIZE];

#define AES_KEY_SIZE 32
#define IV_SIZE 16
#define HMAC_SIZE 32
#define MSG_BUF_SIZE 512

static void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port) {
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

static int initClientNet(char* hostname, int port) {
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    return 0;
}

static int shutdownNetwork() {
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline) {
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len-1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames) {
        char** tag = tagnames;
        while (*tag) {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

static void encryptAndSendMessage(const char* plaintext, size_t len) {
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);
    unsigned char ciphertext[MSG_BUF_SIZE];
    unsigned char hmac[HMAC_SIZE];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sharedSecret, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, (unsigned char*)plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);

    int cipher_len = outlen1 + outlen2;
    HMAC(EVP_sha256(), sharedSecret, KEY_SIZE, ciphertext, cipher_len, hmac, NULL);

    send(sockfd, iv, IV_SIZE, 0);
    send(sockfd, ciphertext, cipher_len, 0);
    send(sockfd, hmac, HMAC_SIZE, 0);
}

static void sendMessage(GtkWidget* w, gpointer data)
{
	char* tags[2] = {"self", NULL};
	tsappend("you: ", tags, 0);

	GtkTextIter mstart, mend;
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
	size_t msgLen = strlen(message);

	// Buffers
	unsigned char encryptedAESKey[256];
	unsigned char cipherText[1024];
	unsigned char signature[256];
	unsigned char mac[32];
	int cipherLen = 0;
	unsigned int sigLen = 0;

	// Encrypt and sign
	encryptThenSign(/* pvtKey, pubKey not used anymore */, NULL, 
	                (unsigned char*)message, msgLen,
	                encryptedAESKey, cipherText, &cipherLen,
	                signature, &sigLen);

	// Generate MAC
	generateMAC(sharedKey, cipherText, cipherLen, mac);

	// Send data with lengths
	uint16_t ekLen = 256;  // fixed
	uint32_t ctLen = (uint32_t)cipherLen;
	uint16_t sigLen16 = (uint16_t)sigLen;

	xwrite(sockfd, &ekLen, sizeof(ekLen));
	xwrite(sockfd, encryptedAESKey, ekLen);

	xwrite(sockfd, &ctLen, sizeof(ctLen));
	xwrite(sockfd, cipherText, ctLen);

	xwrite(sockfd, &sigLen16, sizeof(sigLen16));
	xwrite(sockfd, signature, sigLen16);

	xwrite(sockfd, mac, 32);

	// Show message
	tsappend(message, NULL, 1);

	// Clear and reset
	free(message);
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);
}


static gboolean shownewmessage(gpointer msg) {
    char* tags[2] = {"friend", NULL};
    tsappend("mr. friend: ", tags, 0);
    tsappend((char*)msg, NULL, 1);
    free(msg);
    return 0;
}

void* recvMsg(void* data)
{
	while (1) {
		// Read lengths
		uint16_t ekLen, sigLen;
		uint32_t ctLen;
		if (recv(sockfd, &ekLen, sizeof(ekLen), 0) <= 0) return 0;

		unsigned char encryptedAESKey[256];
		unsigned char cipherText[1024];
		unsigned char signature[256];
		unsigned char mac[32];

		xread(sockfd, encryptedAESKey, ekLen);
		xread(sockfd, &ctLen, sizeof(ctLen));
		xread(sockfd, cipherText, ctLen);
		xread(sockfd, &sigLen, sizeof(sigLen));
		xread(sockfd, signature, sigLen);
		xread(sockfd, mac, 32);

		// MAC check
		if (!verifyMAC(sharedKey, cipherText, ctLen, mac)) {
			fprintf(stderr, "MAC verification failed\n");
			continue;
		}

		// Decrypt and verify signature
		unsigned char decrypted[1024];
		if (!verifyAndDecrypt(encryptedAESKey, cipherText, ctLen, signature, sigLen, decrypted)) {
			fprintf(stderr, "Signature verification or decryption failed\n");
			continue;
		}

		// Add newline and display
		char* m = malloc(strlen((char*)decrypted) + 2);
		strcpy(m, (char*)decrypted);
		strcat(m, "\n");
		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}


int main(int argc, char *argv[]) {
    if (init("params") != 0) {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }
    static struct option long_opts[] = {
        {"connect",  required_argument, 0, 'c'},
        {"listen",   no_argument,       0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX+1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'c':
                if (strnlen(optarg, HOST_NAME_MAX))
                    strncpy(hostname, optarg, HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf(usage, argv[0]);
                return 0;
            case '?':
                printf(usage, argv[0]);
                return 1;
        }
    }

    if (isclient) {
        initClientNet(hostname, port);
        
    } else {
        initServerNet(port);
        
    }
	handshakeProtocol(sockfd, isclient, sharedKey);
	

    GtkBuilder* builder;
    GObject* window;
    GObject* button;
    GObject* transcript;
    GObject* message;
    GError* error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0) {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark  = gtk_text_mark_new(NULL, TRUE);
    window = gtk_builder_get_object(builder, "window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css, "colors.css", NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_USER);
    gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
    gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
    gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

    if (pthread_create(&trecv, 0, recvMsg, 0)) {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();
    shutdownNetwork();
    return 0;
}


