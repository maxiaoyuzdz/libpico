/** \ingroup Communication
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version 1.0
 *
 * @section LICENSE
 *
 * Copyright Pico project, 2016
 *
 * @brief Communication channel support
 * @section DESCRIPTION
 *
 * The channel class provides support for creating and using channels via
 * the Pico Rendezvous Point. It uses curl (HTTP) as the underlying means of
 * interacting with the Rendezvous Point.
 *
 */

/** \addtogroup Communication
 *  @{
 */

#ifndef __CHANNEL_RVP_H
#define __CHANNEL_RVP_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in channel.c
 */

// See buffer.h for more details.

// Function prototypes

DLL_PUBLIC bool channel_set_rvp(RVPChannel * channel);
DLL_PUBLIC bool channel_decode_url_rvp(char const * url, Buffer * address, Buffer * channel);

// Function definitions

#endif

/** @} addtogroup Communication */

