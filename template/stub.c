/**
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version 1.0
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
 * @section DESCRIPTION
 *
 *
 *
 */

#include <stdio.h>
#include <malloc.h>
#include "pico/debug.h"
#include "pico/stub.h"

// Defines

// Structure definitions

struct _Stub {
};

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Stub * stub_new() {
	Stub * stub;

	stub = CALLOC(sizeof(Stub), 1);
	
	return stub;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param stub The object to free.
 */
void stub_delete(Stub * stub) {
	if (stub) {
		FREE(stub);
	}
}


