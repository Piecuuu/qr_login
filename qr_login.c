#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>

EVP_PKEY *evp_keypair = NULL;
char *base64_encoded_public_key = NULL;
int received_hello = 0;
int heartbeat_interval = 0;
int still_run_ws = 1;

struct memory {
  char *response;
  size_t size;
};

static size_t cb(void *data, size_t size, size_t nmemb, void *clientp) {
  size_t realsize = size * nmemb;
  struct memory *mem = (struct memory *)clientp;

  char *ptr = realloc(mem->response, mem->size + realsize + 1);
  if(!ptr)
  return 0;  /* out of memory! */

  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

char *base64_encode(const unsigned char *data, size_t input_length) {
  BIO *bio, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, data, input_length);
  BIO_flush(bio);

  BIO_get_mem_ptr(bio, &bptr);

  char *buffer = (char *)malloc(bptr->length + 1);
  if(buffer == NULL) {
    fprintf(stderr, "Memory allocation error\n");
    return NULL;
  }

  memcpy(buffer, bptr->data, bptr->length);
  buffer[bptr->length] = 0;

  BIO_free_all(bio);

  return buffer;
}

static void base64_decode(const char* in, size_t in_len, unsigned char** out, size_t* out_len) {
  BIO *buff, *b64f;

  b64f = BIO_new(BIO_f_base64());
  buff = BIO_new_mem_buf((void *)in, in_len);
  buff = BIO_push(b64f, buff);
  (*out) = (unsigned char *) malloc(in_len * sizeof(char));

  BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
  BIO_set_close(buff, BIO_CLOSE);
  (*out_len) = BIO_read(buff, (*out), in_len);
  (*out) = (unsigned char *) realloc((void *)(*out), ((*out_len) + 1) * sizeof(unsigned char));
  (*out)[(*out_len)] = '\0';

  BIO_free_all(buff);
}

int rsa_decrypt(const unsigned char *encrypted_data, size_t encrypted_length, unsigned char **decrypted_data, size_t *decrypted_length) {
  if(!evp_keypair) {
    fprintf(stderr, "RSA key pair not available\n");
    return -1;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_keypair, NULL);

  if(!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
      EVP_PKEY_decrypt(ctx, NULL, decrypted_length, encrypted_data, encrypted_length) <= 0)
  {
    fprintf(stderr, "Error initializing or decrypting RSA\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  *decrypted_data = (unsigned char *)malloc(*decrypted_length);
  if(!*decrypted_data) {
    fprintf(stderr, "Memory allocation error\n");
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if(EVP_PKEY_decrypt(ctx, *decrypted_data, decrypted_length, encrypted_data, encrypted_length) <= 0) {
    fprintf(stderr, "Error decrypting RSA\n");
    free(*decrypted_data);
    *decrypted_data = NULL;
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);
  return 0;
}
void remove_newlines_and_spaces(char *str) {
  char *ptr = str;
  char *end = str;

  while(*ptr != '\0') {
    if(*ptr != '\n' && *ptr != ' ') {
      *end = *ptr;
      end++;
    }
    ptr++;
  }

  *end = '\0';
}

int generate_and_export_key_pair()
{
  RAND_poll();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  BIGNUM *e = BN_new();

  if(!ctx || !e || EVP_PKEY_keygen_init(ctx) <= 0 ||
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
    BN_set_word(e, RSA_F4) <= 0 ||
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0 ||
    EVP_PKEY_keygen(ctx, &evp_keypair) <= 0)
  {
    fprintf(stderr, "Error generating RSA key pair\n");
    BN_free(e);
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  BIO *bio_out = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio_out, evp_keypair);

  char *der_data;
  long der_len = BIO_get_mem_data(bio_out, &der_data);

  char *buffer = (char *)malloc(der_len + 1);
  if(buffer == NULL) {
    fprintf(stderr, "Memory allocation error\n");
    return 1;
  }

  memcpy(buffer, der_data, der_len);
  buffer[der_len] = 0;

  // base64_encoded_public_key = base64_encode((const unsigned char *)der_data, der_len);
  char *start = strstr(buffer, "-----BEGIN PUBLIC KEY-----");
  char *end = strstr(buffer, "-----END PUBLIC KEY-----");
  if(start != NULL && end != NULL) {
    size_t header_len = strlen("-----BEGIN PUBLIC KEY-----");
    size_t footer_len = strlen("-----END PUBLIC KEY-----");
    memmove(buffer, start + header_len, end - (start + header_len));
    buffer[end - (start + header_len)] = 0;
  }

  // memcpy(base64_encoded_public_key, buffer, der_len + 1);
  remove_newlines_and_spaces(buffer);
  base64_encoded_public_key = buffer;
  BIO_free(bio_out);
  BN_free(e);
  EVP_PKEY_CTX_free(ctx);

  return 0;
}

int compute_sha256_hash(const unsigned char *data, size_t data_length, char *hash) {
  EVP_MD_CTX *md_ctx;
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, EVP_sha256());
  EVP_DigestUpdate(md_ctx, data, data_length);
  EVP_DigestFinal(md_ctx, (unsigned char *)hash, NULL);
  EVP_MD_CTX_free(md_ctx);
  //hash[32] = '\0'; // Ensure null-terminated string

  return 0;
}
void remove_newline(char *str) {
  size_t len = strlen(str);
  if(len > 0 && str[len - 1] == '\n') {
    str[len - 1] = '\0';  // Replace '\n' with '\0'
  }
}
char *base64_url_safe(const unsigned char *data, size_t input_length) {
  const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t output_length = ((input_length + 2) / 3) * 4;
  char *encoded_data = (char *)malloc(output_length + 1);

  size_t i, j;
  for(i = 0, j = 0; i < input_length; i += 3) {
    uint32_t octet_a = i < input_length ? data[i] : 0;
    uint32_t octet_b = (i + 1) < input_length ? data[i + 1] : 0;
    uint32_t octet_c = (i + 2) < input_length ? data[i + 2] : 0;

    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

    encoded_data[j++] = base64_chars[(triple >> 18) & 63];
    encoded_data[j++] = base64_chars[(triple >> 12) & 63];
    encoded_data[j++] = base64_chars[(triple >> 6) & 63];
    encoded_data[j++] = base64_chars[triple & 63];
  }

  encoded_data[output_length] = '\0';  // Null-terminate the string
  return encoded_data;
}

static int callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  switch(reason) {
    case LWS_CALLBACK_CLIENT_CLOSED:
      fprintf(stdout, "Client closed");
      //exit(0);
      break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      fprintf(stderr, "Connection Error: %s\n", (char *)in);
      exit(0);
      break;

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      fprintf(stderr, "Connection Established\n");
      struct lws *wsi_in = lws_get_child(wsi);

      break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
      char *received_json_str = (char *)in;
      printf("Recieved something: %s\n", (char *)in);
      cJSON *json = cJSON_Parse(received_json_str);

      if(json != NULL) {
        cJSON *op_j = cJSON_GetObjectItemCaseSensitive(json, "op");

        if(op_j) {
          printf("Received op %s\n", op_j->valuestring);
          const char *op = op_j->valuestring;

          if(strcmp(op, "hello") == 0) {
            heartbeat_interval = cJSON_GetObjectItemCaseSensitive(json, "heartbeat_interval")->valueint;
            received_hello = 1;
            char send_json_str[1024];
            sprintf(send_json_str, "{\"op\":\"init\",\"encoded_public_key\":\"%s\"}", base64_encoded_public_key);
            printf("Sent %s\n", send_json_str);
            lws_write(wsi, send_json_str, strlen(send_json_str), LWS_WRITE_TEXT);
          } else if(strcmp(op, "nonce_proof") == 0) {
            unsigned char *base64_encrypted_nonce = cJSON_GetObjectItemCaseSensitive(json, "encrypted_nonce")->valuestring;
            size_t base64_nonce_length = strlen(base64_encrypted_nonce);
            size_t encrypted_length;
            unsigned char *encrypted_nonce;
            base64_decode(base64_encrypted_nonce, base64_nonce_length, &encrypted_nonce, &encrypted_length);
            if(encrypted_nonce) {
              unsigned char *decrypted_data = NULL;
              size_t decrypted_length;

              if(rsa_decrypt(encrypted_nonce, encrypted_length, &decrypted_data, &decrypted_length) == 0) {
                char *hash = malloc(SHA256_DIGEST_LENGTH);
                if(compute_sha256_hash(decrypted_data, decrypted_length, hash) == 0) {
                  char* proof = base64_url_safe(hash, strlen(hash));
                  proof[strlen(proof)-1] = '\0';
                  char send_json_str[1024];
                  sprintf(send_json_str, "{\"op\":\"nonce_proof\",\"proof\":\"%s\"}", proof);
                  printf("Sent %s\n", send_json_str);
                  lws_write(wsi, send_json_str, strlen(send_json_str), LWS_WRITE_TEXT);
                  free(proof);
                }
                free(decrypted_data);
                free(hash);
              }

              free(encrypted_nonce);
            }
          } else if(strcmp(op, "pending_remote_init") == 0) {
            const char* url = "https://discord.com/ra/%s\n";
            const char* fingerprint = cJSON_GetObjectItemCaseSensitive(json, "fingerprint")->valuestring;
            char message[64];

            //snprintf(message, strlen(message), url, fingerprint);
            printf(url, fingerprint);
          } else if(strcmp(op, "pending_login") == 0) {
            const char* ticket = cJSON_GetObjectItemCaseSensitive(json, "ticket")->valuestring;
            struct memory chunk = {0};
            struct curl_slist *list = NULL;
            CURL* curl = curl_easy_init();
            char ticket_body[128];
            sprintf(ticket_body, "{\"ticket\": \"%s\"}", ticket);
            list = curl_slist_append(list, "Content-Type: application/json");
            list = curl_slist_append(list, "Origin: https://discord.com");
            list = curl_slist_append(list, "Referer: https://discord.com/login");
            if(curl) {
              curl_easy_setopt(curl, CURLOPT_URL, "https://discord.com/api/v9/users/@me/remote-auth/login");
              curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
              curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ticket_body);
              curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0");
              curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
              curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

              CURLcode res = curl_easy_perform(curl);
              if(res == CURLM_OK) {
                still_run_ws = 0;
                chunk.response[chunk.size+1] = '\0';
                cJSON* token_enc_json = cJSON_Parse(chunk.response);
                const char* encrypted_base64_token = cJSON_GetObjectItemCaseSensitive(token_enc_json, "encrypted_token")->valuestring;
                size_t base64_token_length = strlen(encrypted_base64_token);
                size_t encrypted_length;
                unsigned char *encrypted_token;
                base64_decode(encrypted_base64_token, base64_token_length, &encrypted_token, &encrypted_length);
                unsigned char *decrypted_token = NULL;
                size_t decrypted_length;
                rsa_decrypt(encrypted_token, encrypted_length, &decrypted_token, &decrypted_length);
                decrypted_token[decrypted_length] = '\0';
                printf("TOKEN: %s\n", decrypted_token);
              }
              free(chunk.response);
              curl_easy_cleanup(curl);
              curl_slist_free_all(list);
              printf("Bye!\n");
              exit(0);
            }
          }
        }

        cJSON_Delete(json);
      }
      break;

    default:
      break;
  }

  return 0;
}

void *lws_service_thread(void *arg) {
  struct lws_context *context = (struct lws_context*)arg;

  while(1) {
    int ret = lws_service(context, 1000);
  }

  pthread_exit(NULL);
}



static struct lws_protocols protocols[] =
  {
    {
      .name = "protocol",     /* Protocol name*/
      .callback = callback,     /* Protocol callback */
      .per_session_data_size = 0, /* Protocol callback 'userdata' size */
      .rx_buffer_size = 0,    /* Receve buffer size (0 = no restriction) */
      .id = 0,          /* Protocol Id (version) (optional) */
      .user = NULL,         /* 'User data' ptr, to access in 'protocol callback */
      .tx_packet_size = 0     /* Transmission buffer size restriction (0 = no restriction) */
    },
    LWS_PROTOCOL_LIST_TERM /* terminator */
};

int main()
{
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
  if(generate_and_export_key_pair() != 0) {
    fprintf(stderr, "Failed to generate and export RSA key pair\n");
    return -1;
  }
  remove_newlines_and_spaces(base64_encoded_public_key);
  printf("Base64-encoded public key: %s\n", base64_encoded_public_key);

  struct lws_context_creation_info info;
  struct lws_client_connect_info connect_info;
  struct lws *wsi;

  memset(&info, 0, sizeof(info));
  memset(&connect_info, 0, sizeof(connect_info));

  info.port = CONTEXT_PORT_NO_LISTEN;
  info.protocols = protocols;
  info.gid = -1;
  info.uid = -1;
  info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  info.client_ssl_ca_filepath = "/etc/ssl/certs/ca-certificates.crt";

  struct lws_context *context = lws_create_context(&info);
  if(!context) {
    fprintf(stderr, "Failed to create libwebsockets context\n");
    return -1;
  }

  connect_info.context = context;
  connect_info.address = "remote-auth-gateway.discord.gg";
  connect_info.port = 443;
  connect_info.path = "/?v=2";
  connect_info.host = connect_info.address;
  connect_info.origin = "discord.com";
  connect_info.protocol = protocols[0].name;
  connect_info.ssl_connection = LCCSCF_USE_SSL;

  // lws_set_log_level(287, NULL);
  // lws_set_log_level(LLL_DEBUG, NULL);
  wsi = lws_client_connect_via_info(&connect_info);

  if(!wsi) {
    fprintf(stderr, "Failed to connect to server\n");
    lws_context_destroy(context);
    return -1;
  }

  pthread_t lws_service_tid;
  if(pthread_create(&lws_service_tid, NULL, lws_service_thread, (void *)context) != 0) {
    perror("pthread_create lws_service");
    return 1;
  }

  do {
    asm(""); // Don't optimise out
  } while(!received_hello); // Block the execution

  int sleepFor = heartbeat_interval / 1000;

  while(1) {
    if(still_run_ws) {
      sleep(sleepFor);
      char send_json_str[256];
      sprintf(send_json_str, "{\"op\":\"heartbeat\"}");
      printf("Sent %s\n", send_json_str);
      lws_write(wsi, send_json_str, strlen(send_json_str), LWS_WRITE_TEXT);
    }
  }


  EVP_PKEY_free(evp_keypair);
  free(base64_encoded_public_key);
  lws_context_destroy(context);
  return 0;
}
