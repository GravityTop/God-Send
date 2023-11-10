#pragma once

#include "includes.h"

#include <stdint.h>

#define SCANNER_MAX_CONNS   350
#define SCANNER_RAW_PPS     410

#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  32

struct scanner_auth {
    unsigned char *username;
    unsigned char *password;
    uint16_t weight_min, weight_max;
    unsigned char username_len, password_len;
};

struct scanner_connection {
    struct scanner_auth *auth;
    int fd;
    time_t last_recv;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP
    } state;
    uint32_t dst_addr;
    uint16_t dst_port;
    size_t rdbuf_pos;
    unsigned char rdbuf[SCANNER_RDBUF_SIZE];
    unsigned char tries;
    unsigned char recv_wo_proc;
};

void scanner_init();
void scanner_kill(void);

void scanner_add_auth_entry(unsigned char *, unsigned char *);
void scanner_clear_auth_entry(void);
