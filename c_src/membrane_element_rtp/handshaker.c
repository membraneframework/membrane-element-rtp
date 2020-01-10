#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../../../Documents/libdtlssrtp/dtls_srtp.h"
#include "../../../../Documents/libdtlssrtp/dsink_udp.h"
#include "handshaker.h"

#define RTP_PACKET_LEN 8192

const char usage_format[] = "Usage: %s [options] [address] [port]\n"
                            "Options:\n"
                            "        -b:       address to bind\n"
                            "        -c:       certificate file\n"
                            "        -k:       private key file\n"
                            "        -s        server mode\n"
                            "        -p:       local port to bind\n";

// option string used by getopt(3).
const char optstr[] = "svb:c:k:h:p:";

// recommended cipher suites.
const char cipherlist[] =
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:"
    "kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:"
    "ECDHE-ECDSA-AES128-SHA256:"
    "ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:"
    "ECDHE-RSA-AES256-SHA384:"
    "ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:"
    "ECDHE-ECDSA-AES256-SHA:"
    "DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:"
    "DHE-RSA-AES256-SHA256:"
    "DHE-RSA-AES256-SHA:"
    "!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK";

/*
 * They need addresses used by functions below, so they are not
 * defined as macros.
 */
const int on = 1, off = 0;

static int exitflag = 0;

// default timeout interval.
static const struct timeval timeout = {5, 0};

// callback used by signal(2)
static void setexit(int sig) {
  if (sig == SIGINT) {
    exitflag = 1;
  }
}

// function to print binary blobs as comma-separated hexadecimals.
int fprinthex(FILE *fp, const char *prefix, const void *b, size_t l) {
  int totallen = 0;
  const char *finger = (const char *)b;
  const char *end = finger + l;
  totallen += fprintf(fp, "%s:        %hhx", prefix, *(finger++));
  for (; finger != end; finger++) {
    totallen += fprintf(fp, ":%hhx", *finger);
  }
  totallen += fputs("\n\n", fp);
  return totallen;
}

// function to specifically print content srtp_key_ptrs objects.
int fprintkeymat(FILE *fp, const srtp_key_ptrs *ptrs) {
  return fputs("********\n", fp) +
         fprinthex(fp, "localkey", ptrs->localkey, MASTER_KEY_LEN) +
         fprinthex(fp, "remotekey", ptrs->remotekey, MASTER_KEY_LEN) +
         fprinthex(fp, "localsalt", ptrs->localsalt, MASTER_SALT_LEN) +
         fprinthex(fp, "remotesalt", ptrs->remotesalt, MASTER_SALT_LEN) +
         fputs("********\n", fp);
}

// function to specifically print fingerprint of X509 objects.
int fprintfinger(FILE *fp, const char *prefix, const X509 *cert) {
  unsigned char fingerprint[EVP_MAX_MD_SIZE];
  unsigned int size = sizeof(fingerprint);
  memset(fingerprint, 0, sizeof(fingerprint));
  if (!X509_digest(cert, EVP_sha1(), fingerprint, &size) || size == 0) {
    fprintf(stderr, "Failed to generated fingerprint from X509 object %p\n",
            cert);
    return 0;
  }
  return fprinthex(fp, prefix, fingerprint, size);
}

int handle_socket_error(void) {
  switch (errno) {
  case EINTR:
    /* Interrupted system call.
     * Just ignore.
     */
    fprintf(stderr, "Interrupted system call!\n");
    return 1;
  case EBADF:
    /* Invalid socket.
     * Must close connection.
     */
    fprintf(stderr, "Invalid socket!\n");
    return 0;
    break;
#ifdef EHOSTDOWN
  case EHOSTDOWN:
    /* Host is down.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    fprintf(stderr, "Host is down!\n");
    return 1;
#endif
#ifdef ECONNRESET
  case ECONNRESET:
    /* Connection reset by peer.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    fprintf(stderr, "Connection reset by peer!\n");
    return 1;
#endif
  case ENOMEM:
    /* Out of memory.
     * Must close connection.
     */
    fprintf(stderr, "Out of memory!\n");
    return 0;
    break;
  case EACCES:
    /* Permission denied.
     * Just ignore, we might be blocked
     * by some firewall policy. Try again
     * and hope for the best.
     */
    fprintf(stderr, "Permission denied!\n");
    return 1;
    break;
  default:
    /* Something unexpected happened */
    fprintf(stderr, "Unexpected error! (errno = %d)\n", errno);
    return 0;
    break;
  }
  return 0;
}

// class to represent ip address in a unified way.
typedef union usockaddr {
  struct sockaddr_storage ss;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
} uaddr;

/*
 * function to convert ip address represent with strings to
 * uaddr objects.
 */
bool makesockaddr(const char *straddr, in_port_t port, uaddr *addr) {
  if ((straddr == NULL) || (strlen(straddr) == 0)) {
    addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
    addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    addr->s6.sin6_addr = in6addr_any;
    addr->s6.sin6_port = htons(port);
  } else {
    if (1 == inet_pton(AF_INET, straddr, &addr->s4.sin_addr)) {
      addr->s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
      addr->s4.sin_port = htons(port);
    } else if (1 == inet_pton(AF_INET6, straddr, &addr->s6.sin6_addr)) {
      addr->s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
      addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      addr->s6.sin6_port = htons(port);
    } else {
      // straddr does contain a valid address.
      return false;
    }
  }
  return true;
}

socklen_t getsocklen(const uaddr *addr) {
  if (addr == NULL) {
    return 0;
  }
  switch (addr->ss.ss_family) {
  case AF_INET:
    return sizeof(struct sockaddr_in);
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
  default:
    return 0;
  }
}

fd_t prepare_udp_socket(const uaddr *addr) {
  fd_t fd = socket(addr->ss.ss_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    return fd;
  }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
             (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on,
             (socklen_t)sizeof(on));
#endif
  if (addr->ss.ss_family == AF_INET) {
    bind(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
  } else {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
    bind(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in6));
  }
  return fd;
}

void prepare_ei_x_buff(ei_x_buff * buff, const char * node_name) {
    ei_x_new_with_version(buff);

    ei_x_encode_tuple_header(buff, 2);
    ei_x_encode_atom(buff, node_name);

    ei_x_encode_tuple_header(buff, 2);
    ei_x_encode_atom(buff, "cnode");
}

void encode_pair_atom_binary(ei_x_buff * buff, const char * atom_name, const uint8_t * binary, 
            int binary_len) {
    ei_x_encode_tuple_header(buff, 2);
    ei_x_encode_atom(buff, atom_name);
    ei_x_encode_binary(buff, (const void *) binary, binary_len);
}

void forward_packet(int ei_fd, erlang_pid * to, const char * node_name, uint8_t * packet, unsigned int packet_len) {
    ei_x_buff out_buff;
    prepare_ei_x_buff(&out_buff, node_name);

    encode_pair_atom_binary(&out_buff, "packet", packet, packet_len);

    ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

void forward_key_ptrs(int ei_fd, erlang_pid * to, const char * node_name, struct srtp_key_ptrs * ptrs) {
    ei_x_buff out_buff;
    prepare_ei_x_buff(&out_buff, node_name);

    ei_x_encode_tuple_header(&out_buff, 4);
    encode_pair_atom_binary(&out_buff, "localkey", ptrs->localkey, MASTER_KEY_LEN);
    encode_pair_atom_binary(&out_buff, "remotekey", ptrs->remotekey, MASTER_KEY_LEN);
    encode_pair_atom_binary(&out_buff, "localsalt", ptrs->localsalt, MASTER_SALT_LEN);
    encode_pair_atom_binary(&out_buff, "remotesalt", ptrs->remotesalt, MASTER_SALT_LEN);

    ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

void respond_to_initial_msg(int ei_fd, erlang_pid * to, const char * node_name) {
    ei_x_buff out_buff;
    prepare_ei_x_buff(&out_buff, node_name);

    ei_x_encode_atom(&out_buff, "ok");

    ei_send(ei_fd, to, out_buff.buff, out_buff.index);
}

int mainloop(fd_t fd, SSL_CTX *cfg, const struct timeval *timeout,
             const int *toexit, const uaddr *peer, int ei_fd, erlang_pid * to, const char * node_name) {

  int ret = EXIT_FAILURE;
  // the side without a valid peer is considered the passive side.
  dtls_sess *dtls = dtls_sess_new(cfg, dsink_udp_getsink(), (peer == NULL));

  dtls_do_handshake(dtls, (void *)fd, (const void *)peer, getsocklen(peer));

  uint8_t payload[RTP_PACKET_LEN];
  while (*toexit == false) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval l_timeout = *timeout;

    uaddr l_peer;
    if (peer != NULL) {
      l_peer = *peer;
    } else {
      memset(&l_peer, 0, sizeof(l_peer));
    }
    socklen_t l_peerlen = sizeof(l_peer);
    int len = 0;

    int selected = select(fd + 1, &rfds, NULL, NULL, &l_timeout);
    if (selected == -1) {
      perror("select()");
      break;
    } else if (selected > 0) {
      // a packet is received.
      memset(payload, 0, sizeof(payload));
      len = recvfrom(fd, payload, sizeof(payload), 0,
                     (struct sockaddr *)&l_peer, &l_peerlen);
      if (len < 0 && !handle_socket_error()) {
        // packet received error!
        break;
      }
      if (packet_is_dtls(payload, len)) {
        len = dtls_sess_put_packet(dtls, (void *)fd, payload, len,
                                   (const void *)&l_peer, l_peerlen);
        if ((len < 0) && SSL_get_error(dtls->ssl, len) == SSL_ERROR_SSL) {
          fprintf(
              stderr,
              "DTLS failure occurred on dtls session %p due to reason '%s'\n",
              dtls, ERR_reason_error_string(ERR_get_error()));
          break;
        }
        if (dtls->type == DTLS_CONTYPE_EXISTING) {
          // SSL_is_init_finished(), print key material.
          {
            X509 *peercert = dtls_sess_get_pear_certificate(dtls);
            if (peercert == NULL) {
              fprintf(stderr, "No certificate was provided by the peer on dtls "
                              "session %p\n",
                      dtls);
              break;
            }
            fprintfinger(stdout, "Fingerprint of peer's cert is ", peercert);
            X509_free(peercert);
          }
          srtp_key_material *km = srtp_get_key_material(dtls);
          if (km == NULL) {
            fprintf(
                stderr,
                "Unable to extract SRTP keying material from dtls session %p\n",
                dtls);
            break;
          }
          srtp_key_ptrs ptrs = {0, 0, 0, 0};
          srtp_key_material_extract(km, &ptrs);
          forward_key_ptrs(ei_fd, to, node_name, &ptrs);
          fprintkeymat(stdout, &ptrs);
          key_material_free(km);
          if (peer == NULL) {
            // demo works as server.
            dtls_sess_setup(dtls);
            continue;
          } else {
            ret = EXIT_SUCCESS;
            break;
          }
        }
      } else {
        forward_packet(ei_fd, to, node_name, payload, RTP_PACKET_LEN);
      }
    } else {
      // no packet arrived, selected() returns for timeout.
      continue;
    }
  }
  dtls_sess_free(dtls);
  return ret;
}

int init() {
    int res = dtls_init_openssl();
    if (!res) {
        perror("OpenSSL initialization failed! quitting.\n");
        return -1;
    } 
    return 0;
}

int get_ssl_ctx(const char * certfile, const char * pkeyfile, SSL_CTX ** ssl_ctx) {
    tlscfg cfg = {0, 0, SRTP_PROFILE_AES128_CM_SHA1_80, cipherlist, 0, 0};

    BIO * fb = BIO_new_file(certfile, "rb");
    cfg.cert = PEM_read_bio_X509(fb, NULL, NULL, NULL);
    BIO_free(fb);
    if (cfg.cert == NULL) {
        perror("Fail to parse certificate file!\n");
        fflush(stderr);
        return -1;
    } else {
        fprintfinger(stdout, "Fingerprint of local cert is ", cfg.cert);
    }

    fb = BIO_new_file(pkeyfile, "rb");
    cfg.pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL);
    BIO_free(fb);
    if (cfg.pkey == NULL) {
        perror("Fail to parse private key file!\n");
        fflush(stderr);
        return -1;
    }

    SSL_CTX * result = dtls_ctx_init(DTLS_VERIFY_FINGERPRINT, NULL, &cfg);
    if (result == NULL) {
        perror("Fail to generate SSL_CTX!\n");
        fflush(stderr);
        return -1;
    }

    *ssl_ctx = result;
    return 0;
}

int get_sock_fd(const char * local_addr, in_port_t local_port, fd_t * sock_fd) {
    uaddr luaddr;
    if (!makesockaddr(local_addr, local_port, &luaddr)) {
        perror("Local address is invalid!\n");
        fflush(stderr);
        return -1;
    }

    *sock_fd = prepare_udp_socket(&luaddr);
    return 0;
}

int dtls_srtp_server(const char * cert_file, const char * pkey_file, const char * local_addr, in_port_t local_port,
            int ei_fd, erlang_pid * to, const char * node_name) {

    if (init() < 0) {
        return 1;
    }

    SSL_CTX * ssl_ctx;
    fd_t sock_fd;

    if (get_ssl_ctx(cert_file, pkey_file, &ssl_ctx) < 0) {
        return -1;
    }

    if (get_sock_fd(local_addr, local_port, &sock_fd) < 0) {
        return -1;
    }
    
    respond_to_initial_msg(ei_fd, to, node_name);

    int res = mainloop(sock_fd, ssl_ctx, &timeout, &exitflag, NULL, ei_fd, to, node_name);
    return res;
}
