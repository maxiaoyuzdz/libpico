/**
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version 1.0
 *
 * @section LICENSE
 *
 * Copyright Pico project, 2016
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


