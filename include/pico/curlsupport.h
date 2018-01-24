/** \ingroup Communication
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of libpico.
 *
 * Libpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with libpico. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *
 * @brief Support functions for communicating using HTTP/S, using curl
 * @section DESCRIPTION
 *
 * The curl library uses callbacks to provide or return data to or from a 
 * server. These functions offer some standard approaches to hooking in to this
 * using the libpico dynamic buffers.
 *
 */

/** \addtogroup Communication
 *  @{
 */

#ifndef __CURLSUPPORT_H
#define __CURLSUPPORT_H (1)

// Defines

// Structure definitions

// Function prototypes

size_t write_data(void * ptr, size_t size, size_t nmemb, void * userp);
size_t print_data(void * ptr, size_t size, size_t nmemb, void * userp);
size_t log_data(void * ptr, size_t size, size_t nmemb, void * userp);

// Function definitions

#endif

/** @} addtogroup Communication */

