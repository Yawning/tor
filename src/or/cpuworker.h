/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file cpuworker.h
 * \brief Header file for cpuworker.c.
 **/

#ifndef TOR_CPUWORKER_H
#define TOR_CPUWORKER_H

void cpu_init(void);
void cpuworkers_rotate_keyinfo(void);

struct create_cell_t;
int assign_onionskin_server_to_cpuworker(or_circuit_t *circ,
                                         struct create_cell_t *onionskin);

uint64_t estimated_usec_for_onionskins(uint32_t n_requests,
                                       uint16_t onionskin_type);
void cpuworker_log_onionskin_overhead(int severity, int onionskin_type,
                                      const char *onionskin_type_name);
void cpuworker_cancel_circ_handshake(circuit_t *circ);

struct created_cell_t;
int assign_onionskin_client_to_cpuworker(origin_circuit_t *circ,
                                         const struct created_cell_t *extended,
                                         crypt_path_t *hop);
void cpuworker_cancel_client_handshake(origin_circuit_t *circ);

#endif

