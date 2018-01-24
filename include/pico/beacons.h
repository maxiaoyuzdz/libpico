/** \ingroup Storage
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
 * @brief Store Bluetooth MAC info for sending beacons
 * @section DESCRIPTION
 *
 * When using Pico with Bluetooth Classic, beacons are periodically sent out
 * to all of the devices that have previously paired with Pico. To do this,
 * a file `bluetooth.txt` is stored containing a list of MAC addresses to send
 * these beacons to.
 *
 * This file contains functions for managing this list of MACs, as well as
 * importing them from file and exporting them out again. The code manages
 * a linked list of devices, along with assoicated data (e.g. the
 * commitment of the user associated with the device). This allows beacons to
 * be sent out to some or all devices depending on what's needed.
 *
 */

/** \addtogroup Storage
 *  @{
 */

#ifndef __BEACONS_H
#define __BEACONS_H (1)

#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in beacons.c
 */
typedef struct _Beacons Beacons;

/**
 * The internal structure can be found in beacons.c
 */
typedef struct _BeaconDevice BeaconDevice;

// Function prototypes

DLL_PUBLIC Beacons * beacons_new();
DLL_PUBLIC void beacons_delete(Beacons * beacons);

DLL_PUBLIC unsigned int beacons_load_devices(Beacons * beacons, char const * filename, Users const * users);
DLL_PUBLIC bool beacons_export_devices(Beacons const * beacons, char const * file);
DLL_PUBLIC BeaconDevice * beacons_add_device(Beacons * beacons, char const * address, Buffer const * commitment);

DLL_PUBLIC void beacons_set_data(BeaconDevice * beacondevice, void * data);
DLL_PUBLIC void * beacons_get_data(BeaconDevice * beacondevice);
DLL_PUBLIC char const * beacons_get_address(BeaconDevice * beacondevice) ;
DLL_PUBLIC unsigned int beacons_get_device_num(Beacons * beacons);
DLL_PUBLIC BeaconDevice * beacons_get_next(BeaconDevice * beacondevice);
DLL_PUBLIC BeaconDevice * beacons_get_first(Beacons * beacons);

// Function definitions

#endif

/** @} addtogroup Storage */

