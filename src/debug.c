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

#include <stdio.h>
#include <malloc.h>
#include "pico/debug.h"

// Defines

#ifdef PICO_DEBUG
// Structure definitions

// Function prototypes

// Function definitions

static int allocations = 0;

/**
 * Initialise debug functions. At present this just resets the count for the
 * number of allocated blocks.
 * This is only called if PICO_DEBUG is defined.
 *
 */
void debug_init() {
	allocations = 0;
}

/**
 * Finalise debug functions. Prints out the difference between the number
 * of blocks allocated and the number released.
 * This is only called if PICO_DEBUG is defined.
 *
 */
void debug_final() {
	printf("Remaining allocations: %d\n", allocations);
}

/**
 * Debug malloc. Wraps the standard malloc but also keeps track of how many
 * blocks have been allocated.
 * This is only called if PICO_DEBUG is defined.
 *
 * @param __size Size of the heap block to be allocated
 * @return pointer to the allocated block
 */
void * debug_malloc(size_t __size) {
	allocations++;
	return malloc(__size);
}

/**
 * Debug calloc. Wraps the standard calloc but also keeps track of how many
 * blocks have been allocated.
 * This is only called if PICO_DEBUG is defined.
 *
 * @param __nmemb Size of each item to allocate
 * @param __size Number of items to allocate
 * @return pointer to the allocated block
 */
void * debug_calloc(size_t __nmemb, size_t __size) {
	allocations++;
	return calloc(__nmemb, __size);
}

/**
 * Debug realloc. Wraps the standard realloc but also keeps track of how many
 * blocks have been allocated.
 * This is only called if PICO_DEBUG is defined.
 *
 * @param __ptr Pointer to the existing block to be resized
 * @param __size New size of the heap block to be resized
 * @return pointer to the block with the new size
 */
void * debug_realloc(void *__ptr, size_t __size) {
	return realloc(__ptr, __size);
}

/**
 * Debug free. Wraps the standard free but also keeps track of how many
 * blocks have been allocated.
 * This is only called if PICO_DEBUG is defined.
 *
 * @param __ptr Heap block to free
 */
void debug_free(void *__ptr) {
	allocations--;
	free(__ptr);
}

#endif

/** @} addtogroup Debug */

