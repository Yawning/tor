/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file netlink.h
 * \brief Headers for netlink.h
 **/

#ifndef TOR_NETLINK_H
#define TOR_NETLINK_H

#include "orconfig.h"
#include "address.h"

int get_interface_address_netlink(int severity, sa_family_t family,
                                  tor_addr_t *addr);

#endif
