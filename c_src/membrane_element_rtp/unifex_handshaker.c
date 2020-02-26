#include "unifex_handshaker.h"
#include <libdtlssrtp/handshaker_utils.h>

#include <stdio.h>

static const struct timeval timeout = {5, 0};

void packet_sender(void *env, const uint8_t *content, unsigned int size) {
  char *copy = (char *)malloc(size + 1);
  memcpy(copy, content, size);
  copy[size] = 0;

  send_packet((UnifexEnv *)env, copy);

  free(copy);
}

void keys_sender(void *env, const uint8_t *localkey, const uint8_t *remotekey,
                 const uint8_t *localsalt, const uint8_t *remotesalt) {
  send_key_set((UnifexEnv *)env, (const char *)localkey,
               (const char *)remotekey, (const char *)localsalt,
               (const char *)remotesalt);
}

void start_server(UnifexEnv *env, char *cert_file, char *pkey_file,
                  char *local_addr, int local_port) {

  if (init() < 0) {
    send_error(env, "SSL init failed");
    return;
  }

  SSL_CTX *ssl_ctx;
  fd_t sock_fd;

  if (get_ssl_ctx(cert_file, pkey_file, &ssl_ctx) < 0) {
    send_error(env, "Reading SSL context failed");
    return;
  }

  if (get_sock_fd(local_addr, local_port, &sock_fd) < 0) {
    send_error(env, "Binding on socket failed");
    return;
  }

  send_server_running(env);

  mainloop(sock_fd, ssl_ctx, &timeout, NULL, (void *)env, &packet_sender,
           &keys_sender);
}
