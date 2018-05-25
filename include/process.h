/**
 * @file process.h
 * @brief Function prototypes for @p process.c, packet direction macros
 */
#pragma once

#include "iface.h"

/** @name Frame/packet direction */
#define PROCESS_EGRESS		1
#define PROCESS_INGRESS		0

int process_filter(struct peapod_packet packet, struct iface_t *iface, uint8_t dir);
void process_script(struct peapod_packet packet, struct action_t *action, uint8_t dir);