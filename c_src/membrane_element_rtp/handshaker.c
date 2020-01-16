#include "handshaker.h"
#include <arpa/inet.h>
#include <libdtlssrtp/handshaker_utils.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

#define RTP_PACKET_LEN 8192

static const struct timeval timeout = {5, 0};

static void prepare_ei_x_buff(ei_x_buff *buff, const char *node_name) {
  ei_x_new_with_version(buff);
  ei_x_encode_tuple_header(buff, 2);
  ei_x_encode_atom(buff, node_name);
}

static void encode_pair_atom_binary(ei_x_buff *buff, const char *atom_name,
                                    const uint8_t *binary, int binary_len) {
  ei_x_encode_tuple_header(buff, 2);
  ei_x_encode_atom(buff, atom_name);
  ei_x_encode_binary(buff, (const void *)binary, binary_len);
}

static void forward_packet(int ei_fd, erlang_pid *to, const char *node_name,
                           uint8_t *packet, unsigned int packet_len) {
  ei_x_buff out_buff;
  prepare_ei_x_buff(&out_buff, node_name);

  encode_pair_atom_binary(&out_buff, "packet", packet, packet_len);

  ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

static void forward_key_ptrs(int ei_fd, erlang_pid *to, const char *node_name,
                             struct srtp_key_ptrs *ptrs) {
  ei_x_buff out_buff;
  prepare_ei_x_buff(&out_buff, node_name);

  ei_x_encode_tuple_header(&out_buff, 4);
  encode_pair_atom_binary(&out_buff, "localkey", ptrs->localkey,
                          MASTER_KEY_LEN);
  encode_pair_atom_binary(&out_buff, "remotekey", ptrs->remotekey,
                          MASTER_KEY_LEN);
  encode_pair_atom_binary(&out_buff, "localsalt", ptrs->localsalt,
                          MASTER_SALT_LEN);
  encode_pair_atom_binary(&out_buff, "remotesalt", ptrs->remotesalt,
                          MASTER_SALT_LEN);

  ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

static void respond_to_initial_msg(int ei_fd, erlang_pid *to,
                                   const char *node_name) {
  ei_x_buff out_buff;
  prepare_ei_x_buff(&out_buff, node_name);

  ei_x_encode_atom(&out_buff, "ok");

  ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

int dtls_srtp_server(const char *cert_file, const char *pkey_file,
                     const char *local_addr, in_port_t local_port, int ei_fd,
                     erlang_pid *to, const char *node_name) {

  if (init() < 0) {
    return -1;
  }

  SSL_CTX *ssl_ctx;
  fd_t sock_fd;

  if (get_ssl_ctx(cert_file, pkey_file, &ssl_ctx) < 0) {
    return -1;
  }

  if (get_sock_fd(local_addr, local_port, &sock_fd) < 0) {
    return -1;
  }

  respond_to_initial_msg(ei_fd, to, node_name);

  int res = mainloop(sock_fd, ssl_ctx, &timeout, NULL, ei_fd, to, node_name,
                     &forward_packet, &forward_key_ptrs);
  return res;
}
