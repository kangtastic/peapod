/**
 * @file iface.h
 * @brief Function prototypes for @p iface.c.
 */
#pragma once

#include "parser.h"

int iface_init(struct iface_t *ifaces, int epfd);
int iface_count(struct iface_t *ifaces);
void iface_reset_flags(struct iface_t *iface);
int iface_set_flags(struct iface_t *iface);
int iface_set_mac(struct iface_t *iface, u_char *source);
char *iface_strmac(u_char *mac);
