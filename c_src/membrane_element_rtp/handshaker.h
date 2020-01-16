#pragma once

#include <ei.h>

int dtls_srtp_server(const char *cert_file, const char *pkey_file,
                     const char *local_addr, in_port_t local_port, int ei_fd,
                     erlang_pid *to, const char *node_name);
