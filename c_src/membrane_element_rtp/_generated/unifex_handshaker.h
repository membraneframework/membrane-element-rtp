#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifndef _REENTRANT
#define _REENTRANT

#endif
#include <ei_connect.h>
#include <erl_interface.h>

#include <unifex/cnode_utils.h>
#include "../unifex_handshaker.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UnifexState {
  void * field;
} UnifexState;
typedef UnifexState State;

struct UnifexStateWrapper {
  UnifexState *state;
};

void unifex_release_state(UnifexEnv *env, UnifexState *state);
UnifexState *unifex_alloc_state(UnifexEnv *env);
void handle_destroy_state(UnifexEnv *env, UnifexState *state);

void start_server(cnode_context * ctx, char* cert_file, char* pkey_file, char* local_addr, int local_port);

void start_server_caller(const char * in_buff, int * index, cnode_context * ctx);
void send_key_set(cnode_context * ctx, const char* localkey, const char* remotekey, const char* localsalt, const char* remotesalt);
void send_packet(cnode_context * ctx, const char* content);
void send_server_running(cnode_context * ctx);
void send_error(cnode_context * ctx, const char* reason);

#ifdef __cplusplus
}
#endif
