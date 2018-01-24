/** \ingroup Debug
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
 * @brief Useful debug functionality
 * @section DESCRIPTION
 *
 * The debug interface provides some methods for instrumenting memory 
 * management (malloc, calloc, realloc, free). The PICO_DEBUG define
 * can be used to turn on and off this functionality. When turned off
 * the instrumentation is completely removed from the compiled library.
 *
 */

/** \addtogroup Debug
 *  @{
 */

#ifndef __DEBUG_H
#define __DEBUG_H (1)

#include <stdio.h>

// Defines

//#define PICO_DEBUG (1)
#undef PICO_DEBUG

#ifdef PICO_DEBUG
#define MALLOC debug_malloc
#define CALLOC debug_calloc
#define REALLOC debug_realloc
#define FREE debug_free
#define DEBUG_INIT debug_init()
#define DEBUG_FINAL debug_final()
#else
#define MALLOC malloc
#define CALLOC calloc
#define REALLOC realloc
#define FREE free
#define DEBUG_INIT
#define DEBUG_FINAL
#endif

// Structure definitions

// Function prototypes

#ifdef PICO_DEBUG
void debug_init();
void debug_final();

void * debug_malloc (size_t __size);
void * debug_calloc (size_t __nmemb, size_t __size);
void * debug_realloc (void *__ptr, size_t __size);
void debug_free (void *__ptr);
#endif

// Function definitions

#endif

/** @} addtogroup Debug */

