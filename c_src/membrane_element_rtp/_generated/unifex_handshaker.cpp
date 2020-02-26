#include <stdio.h>
#include "unifex_handshaker.h"

void handle_destroy_state(UnifexEnv *env, State *state) {}

size_t unifex_state_wrapper_sizeof() {
  return sizeof(struct UnifexStateWrapper);
}

void unifex_release_state(UnifexEnv *env, UnifexState *state) {
  UnifexStateWrapper *wrapper =
      (UnifexStateWrapper *) malloc(sizeof(UnifexStateWrapper));
  wrapper->state = state;
  add_item(env->released_states, wrapper);
}

UnifexState *unifex_alloc_state(UnifexEnv *env) {
  return (UnifexState *)malloc(sizeof(UnifexState));
}

void start_server_caller(const char * in_buff, int * index, cnode_context * ctx) {
  char cert_file[2048];
  long cert_file_len;
  ei_decode_binary(in_buff, index, (void *) cert_file, &cert_file_len);
  cert_file[cert_file_len] = 0;

char pkey_file[2048];
  long pkey_file_len;
  ei_decode_binary(in_buff, index, (void *) pkey_file, &pkey_file_len);
  pkey_file[pkey_file_len] = 0;

char local_addr[2048];
  long local_addr_len;
  ei_decode_binary(in_buff, index, (void *) local_addr, &local_addr_len);
  local_addr[local_addr_len] = 0;

long long local_port;
ei_decode_longlong(in_buff, index, &local_port);

  ctx->released_states = new_state_linked_list();

  start_server(ctx, cert_file, pkey_file, local_addr, local_port);

  free_states(ctx, ctx->released_states, ctx->wrapper);
}

void send_key_set(cnode_context * ctx, const char* localkey, const char* remotekey, const char* localsalt, const char* remotesalt) {
  ei_x_buff * out_buff = (ei_x_buff *) malloc(sizeof(ei_x_buff));
  ei_x_new_with_version(out_buff);
  ei_x_encode_tuple_header(out_buff, 5);

  char label_key_set[] = "key_set";
  ei_x_encode_atom(out_buff, label_key_set);

  long localkey_len = (long) strlen(localkey);
  ei_x_encode_binary(out_buff, localkey, localkey_len);

  long remotekey_len = (long) strlen(remotekey);
  ei_x_encode_binary(out_buff, remotekey, remotekey_len);

  long localsalt_len = (long) strlen(localsalt);
  ei_x_encode_binary(out_buff, localsalt, localsalt_len);

  long remotesalt_len = (long) strlen(remotesalt);
  ei_x_encode_binary(out_buff, remotesalt, remotesalt_len);

  sending_and_freeing(ctx, out_buff);
  free(out_buff);
}

void send_packet(cnode_context * ctx, const char* content) {
  ei_x_buff * out_buff = (ei_x_buff *) malloc(sizeof(ei_x_buff));
  ei_x_new_with_version(out_buff);
  ei_x_encode_tuple_header(out_buff, 2);

  char label_packet[] = "packet";
  ei_x_encode_atom(out_buff, label_packet);

  long content_len = (long) strlen(content);
  ei_x_encode_binary(out_buff, content, content_len);

  sending_and_freeing(ctx, out_buff);
  free(out_buff);
}

void send_server_running(cnode_context * ctx) {
  ei_x_buff * out_buff = (ei_x_buff *) malloc(sizeof(ei_x_buff));
  ei_x_new_with_version(out_buff);
  ei_x_encode_tuple_header(out_buff, 1);

  char label_server_running[] = "server_running";
  ei_x_encode_atom(out_buff, label_server_running);

  sending_and_freeing(ctx, out_buff);
  free(out_buff);
}

void send_error(cnode_context * ctx, const char* reason) {
  ei_x_buff * out_buff = (ei_x_buff *) malloc(sizeof(ei_x_buff));
  ei_x_new_with_version(out_buff);
  ei_x_encode_tuple_header(out_buff, 2);

  char label_error[] = "error";
  ei_x_encode_atom(out_buff, label_error);

  long reason_len = (long) strlen(reason);
  ei_x_encode_binary(out_buff, reason, reason_len);

  sending_and_freeing(ctx, out_buff);
  free(out_buff);
}

int handle_message(int ei_fd, const char *node_name, erlang_msg emsg,
            ei_x_buff *in_buff, struct UnifexStateWrapper* state) {
  int index = 0;
  int version;
  ei_decode_version(in_buff->buff, &index, &version);

  int arity;
  ei_decode_tuple_header(in_buff->buff, &index, &arity);

  char fun_name[2048];
  ei_decode_atom(in_buff->buff, &index, fun_name);

  cnode_context ctx = {
    .node_name = node_name,
    .ei_fd = ei_fd,
    .e_pid = &emsg.from,
    .wrapper = state
  };

  if (strcmp(fun_name, "start_server") == 0) {
    start_server_caller(in_buff->buff, &index, &ctx);
  }
 else {
  char err_msg[4000];
  strcpy(err_msg, "function ");
  strcat(err_msg, fun_name);
  strcat(err_msg, " not available");
  sending_error(&ctx, err_msg);
}

  return 0;
}

void handle_destroy_state_wrapper(UnifexEnv *env, struct UnifexStateWrapper *wrapper) {
  handle_destroy_state(env, wrapper->state);
}

int wrappers_cmp(struct UnifexStateWrapper *a, struct UnifexStateWrapper *b) {
  return a->state == b->state ? 0 : 1;
}

void free_state(UnifexStateWrapper *wrapper) {
  free(wrapper->state);
}

int main(int argc, char ** argv) {
  return main_function(argc, argv);
}
