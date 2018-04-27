#pragma once

#define PROCESS_EGRESS		1
#define PROCESS_INGRESS		0

int process_filter(struct peapod_packet packet, struct iface_t *iface, uint8_t dir);
//int process_filter_ingress(struct peapod_packet packet, struct iface_t *iface);
//void process_script_egress(struct peapod_packet packet, struct action_t *action);
//void process_script_ingress(struct peapod_packet packet, struct action_t *action);
void process_script(struct peapod_packet packet, struct action_t *action, uint8_t dir);