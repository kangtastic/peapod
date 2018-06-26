/**
 * @file process.h
 * @brief Function prototypes for @p process.c, packet direction symbols
 */
#pragma once

#include "iface.h"

#define PROCESS_INGRESS		0	/**< @brief Ingress phase */
#define PROCESS_EGRESS		1	/**< @brief Egress phase */

int process_filter(struct peapod_packet packet);
void process_script(struct peapod_packet packet);
