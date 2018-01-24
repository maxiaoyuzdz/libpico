/**
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2018
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
 * @brief Unit tests for the beacons data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the Beacons data type.
 *
 */

#include <check.h>
#include <stdbool.h>
#include <unistd.h>
#include <pico/shared.h>
#include <pico/users.h>
#include <pico/base64.h>
#include "../include/pico/beacons.h"

// Defines

#define EXAMPLE_USERS_FILE "# Comment line 1\n" \
	"# Comment line 2\n" \
	"Pachelbel:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEam0K8bMrRAfWtwhB8yS7PA7tUBmAlnoPRxrj0SFdyqUs8mwMw2Rrg/9QGGUc2m6cpW8Cyrx/wvwycmMuSGGy5w==:TaajhTIRojhTIRoAHqDpyg==\n\n" \
	"# Comment line 3\n\n" \
	"Pachelbel:nFQ7rNMLeNABxk/rRJrCN8/pmYG291z77Sk5Zc5KW6E=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENnDeu8fqrxx55e9IyQGlpTl3+JsnVdhi8fjTbaTxablYL+H0aQg3GMc+PgTZorbsPmkLug5LkE/LTI2Ui3cCEQ==:Lkgxxsd02/VrBPPBdiIkfw==\n" \
	"# Comment line 4\n"\
	"# Comment line 5\n"\
	"# Comment line 6\n"\
	"Bruch:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELs0ppPjtpliRKkTW7OMKnKsjuZPKS/Ud7KmyDaO6zWeGnuJFRUmZ4eI7INViqliMvRxgnxFYuNkSIXZ9ND6MfA==:RO+lGHwoppll7390vs9Cqw==\n"\
	"# Comment line 7\n"\
	"# Comment line 8\n"\
	"# Comment line 9\n"\
	"# Comment line 10\n\n"\
	"Schoenberg:NEF48sOIY9LZP9Wsx3auBgG8pIAqqDVJHM2PjCNe+/E=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFsRBMNOMmOFQiHn7nG0LqExAGvIs36wOETfYYS10QH4gCx+rX/xcWXZxmvb++6ZWILZ7tUDrCM8QVLyHBWwunQ==:AA95F667sdkji8Zz9tLSew==\n"\
	"Monteverdi:HBZ9B+kioDLkgdtraPqA+2pTDBBhqFm85HD1KqazgEM=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4V3SujOm67S9x93sCegYP18x/HxyUgA2u6tqcGXcVPZ2S6/uhAYmPBTYz8fMP2NQaaIcocg7TQZf+XMDnY1yBQ==:W/Lyjj8ioJHGDO9jejdfGQ==\n"\
	"# Comment line penultimate\n"\
	"# Comment line last\n"

#define EXAMPLE_BLUETOOTH_FILE "# Header comments\n" \
	"# More header comments\n" \
	"\n" \
	"\n" \
	"50:56:a8:04:08:ac\n" \
	"#9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"9c:5c:f9:00:32:5a\n" \
	"9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"#ec:88:92:74:84:1d:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=\n" \
	"ec:88:92:74:84:1d:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=\n" \
	"22:56:87:34:33:11:dSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"#blah\n" \
	"9c:5c:f9:00:32:12:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"12:34:56:74:84:1d:dSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"34:56:74:84:1d:dSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"34:56:74:84:1d:Garbage:GarbagedSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"\n" \
	"blah\n" \
	"ec:88:92:74:84:1d\n" \
	"12:34:56:74:84:1d:nFQ7rNMLeNABxk/rRJrCN8/pmYG291z77Sk5Zc5KW6E=\n" \
	"#9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"#The End\n"

#define VALID_BLUETOOTH_FILE "# Header comments\n" \
	"# More header comments\n" \
	"\n" \
	"\n" \
	"50:56:a8:04:08:ac\n" \
	"#9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"9c:5c:f9:00:32:5a\n" \
	"9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"#ec:88:92:74:84:1d:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=\n" \
	"ec:88:92:74:84:1d:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=\n" \
	"22:56:87:34:33:11:dSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"#blah\n" \
	"9c:5c:f9:00:32:12:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"12:34:56:74:84:1d:dSeLn4JN2N2HJVRegQxIWI8gDit4PkPPdAyMvMuFM7w=\n" \
	"\n" \
	"ec:88:92:74:84:1d\n" \
	"12:34:56:74:84:1d:nFQ7rNMLeNABxk/rRJrCN8/pmYG291z77Sk5Zc5KW6E=\n" \
	"#9c:5c:f9:00:32:5a:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=\n" \
	"#The End\n"

#define USERS_FILENAME_TEMPLATE "/tmp/pico_users_XXXXXX.txt"
#define BLUETOOTH_FILENAME_TEMPLATE "/tmp/bluetooth_users_XXXXXX.txt"
#define IMPORT_FILENAME_TEMPLATE "/tmp/bluetooth_import_XXXXXX.txt"
#define EXPORT_FILENAME_TEMPLATE "/tmp/bluetooth_export_XXXXXX.txt"

// Structure definitions

// Function prototypes

// Function definitions

START_TEST(test_load) {
	int usersfdoutput;
	int bluetoothfdoutput;
	FILE * output;
	char * usersfilename;
	char * bluetoothfilename;
	Users * users;
	Users * filtered;
	Beacons * beacons;
	unsigned int devices;
	int usercount;

	users = users_new();
	filtered = users_new();

	// Generate filenames of temporary files to use
	usersfilename = malloc(sizeof(USERS_FILENAME_TEMPLATE) + 1);
	strcpy(usersfilename, USERS_FILENAME_TEMPLATE);
	usersfdoutput = mkstemps(usersfilename, 4);
	ck_assert(usersfdoutput >= 0);

	// Output example users.txt file
	output = fdopen(usersfdoutput, "w");
	ck_assert(output != NULL);
	if (output) {
		fputs(EXAMPLE_USERS_FILE, output);
		fclose(output);
	}

	// Generate filenames of temporary files to use
	bluetoothfilename = malloc(sizeof(BLUETOOTH_FILENAME_TEMPLATE) + 1);
	strcpy(bluetoothfilename, BLUETOOTH_FILENAME_TEMPLATE);
	bluetoothfdoutput = mkstemps(bluetoothfilename, 4);
	ck_assert(bluetoothfdoutput >= 0);

	// Output example bluetooth.txt file
	output = fdopen(bluetoothfdoutput, "w");
	ck_assert(output != NULL);
	if (output) {
		fputs(EXAMPLE_BLUETOOTH_FILE, output);
		fclose(output);
	}

	//fprintf(stderr, "Files: %s, %s\n", usersfilename, bluetoothfilename);

	// Load the file in as a list of users
	users_load(users, usersfilename);

	// Check the correct number of devices are loaded from the Bluetooth file
	beacons = beacons_new();
	devices = beacons_load_devices(beacons, bluetoothfilename, users);
	ck_assert_int_eq(devices, 7);
	beacons_delete(beacons);

	// Check the correct number of devices are loaded from the Bluetooth file
	beacons = beacons_new();
	devices = beacons_load_devices(beacons, bluetoothfilename, NULL);
	ck_assert_int_eq(devices, 9);
	beacons_delete(beacons);

	// Check the correct number of devices are loaded from the Bluetooth file
	usercount = users_filter_by_name(users, "Bruch", filtered);
	ck_assert_int_eq(usercount, 1);
	beacons = beacons_new();
	devices = beacons_load_devices(beacons, bluetoothfilename, filtered);
	ck_assert_int_eq(devices, 5);
	beacons_delete(beacons);

	// Check the correct number of devices are loaded from the Bluetooth file
	usercount = users_filter_by_name(users, "Pachelbel", filtered);
	ck_assert_int_eq(usercount, 2);
	beacons = beacons_new();
	devices = beacons_load_devices(beacons, bluetoothfilename, filtered);
	ck_assert_int_eq(devices, 5);
	beacons_delete(beacons);

	// Check the correct number of devices are loaded from the Bluetooth file
	usercount = users_filter_by_name(users, "Debussy", filtered);
	ck_assert_int_eq(usercount, 0);
	beacons = beacons_new();
	devices = beacons_load_devices(beacons, bluetoothfilename, filtered);
	ck_assert_int_eq(devices, 3);
	beacons_delete(beacons);

	// Delete the temporary files
	close(usersfdoutput);
	close(bluetoothfdoutput);
	unlink(usersfilename);
	unlink(bluetoothfilename);

	// Tidy up like a pro
	users_delete(users);
	users_delete(filtered);
	free(usersfilename);
	free(bluetoothfilename);
}
END_TEST

START_TEST(test_export) {
	char const * text = VALID_BLUETOOTH_FILE;
	int importfdoutput;
	int exportfdoutput;
	FILE * output;
	FILE * input;
	char * importfilename;
	char * exportfilename;
	Beacons * beacons;
	unsigned int devices;
	char * imported;
	size_t length;
	size_t size;

	beacons = beacons_new();

	// Generate filename of temporary files to import
	importfilename = malloc(sizeof(IMPORT_FILENAME_TEMPLATE) + 1);
	strcpy(importfilename, IMPORT_FILENAME_TEMPLATE);
	importfdoutput = mkstemps(importfilename, 4);
	ck_assert(importfdoutput >= 0);

	// Output example bluetooth.txt file
	output = fdopen(importfdoutput, "w");
	ck_assert(output != NULL);
	if (output) {
		fputs(text, output);
		fclose(output);
	}

	// Generate filename of temporary file to export to
	exportfilename = malloc(sizeof(EXPORT_FILENAME_TEMPLATE) + 1);
	strcpy(exportfilename, EXPORT_FILENAME_TEMPLATE);
	exportfdoutput = mkstemps(exportfilename, 4); 
	ck_assert(exportfdoutput >= 0);

	//fprintf(stderr, "Files: %s, %s\n", importfilename, exportfilename);

	// Load the file in as a list of devices
	devices = beacons_load_devices(beacons, importfilename, NULL);
	ck_assert_int_eq(devices, 9);

	beacons_export_devices(beacons, exportfilename);

	// Import the exported bluetooth.txt file
	length = strlen(text);
	size = 0;
	imported = malloc(sizeof(VALID_BLUETOOTH_FILE) + 3);
	input = fdopen(exportfdoutput, "r");
	ck_assert(input != NULL);
	if (input) {
		size = fread(imported, sizeof(char), length + 2, input);
		imported[size] = 0;
		fclose(input);
	}

	// Delete the temporary files
	close(importfdoutput);
	close(exportfdoutput);
	unlink(importfilename);
	unlink(exportfilename);

	// Check the original text and exported file are the same
	ck_assert_int_eq(size, length);
	ck_assert_str_eq(text, imported);

	// Tidy up like a pro
	beacons_delete(beacons);
	free(importfilename);
	free(exportfilename);
}
END_TEST

START_TEST(test_add_devices) {
	Beacons * beacons;
	unsigned int num;
	BeaconDevice * beacondevice;
	Buffer * commitment;
	Buffer * base64encoded;
	char const * address;

	beacons = beacons_new();
	commitment = buffer_new(0);
	base64encoded = buffer_new(0);

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 0);

	beacondevice = beacons_get_first(beacons);
	ck_assert(beacondevice == NULL);

	buffer_append_string(base64encoded, "XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=");
	base64_decode_buffer(base64encoded, commitment);

	// Add some different devices
	beacondevice = beacons_add_device(beacons, "ab:13:45:23:f6:34", commitment);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:45:23:f6:34");

	beacondevice = beacons_add_device(beacons, "ab:13:11:23:f1:34:92", NULL);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:11:23:f1:34");

	beacondevice = beacons_add_device(beacons, "00:11:bb:ff:aa:11", NULL);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "00:11:bb:ff:aa:11");

	beacondevice = beacons_get_first(beacons);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:45:23:f6:34");

	beacondevice = beacons_get_next(beacondevice);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:11:23:f1:34");

	beacondevice = beacons_get_next(beacondevice);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "00:11:bb:ff:aa:11");

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 3);

	// Add some repeat devices
	beacondevice = beacons_add_device(beacons, "00:11:bb:ff:aa:11", NULL);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "00:11:bb:ff:aa:11");

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 3);

	beacondevice = beacons_add_device(beacons, "ab:13:45:23:f6:34", commitment);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:45:23:f6:34");

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 3);

	beacondevice = beacons_add_device(beacons, "ab:13:45:23:f6:34:21", commitment);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:45:23:f6:34");

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 3);

	// And finally, only a partial repeat
	beacondevice = beacons_add_device(beacons, "ab:13:11:23:f1:34", commitment);
	address = beacons_get_address(beacondevice);
	ck_assert_str_eq(address, "ab:13:11:23:f1:34");

	num = beacons_get_device_num(beacons);
	ck_assert_int_eq(num, 4);

	beacons_delete(beacons);
	buffer_delete(commitment);
	buffer_delete(base64encoded);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Pico Bluetooth Beacon");

	// Base64 test case
	tc = tcase_create("Beacons");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, test_load);
	tcase_add_test(tc, test_export);
	tcase_add_test(tc, test_add_devices);

	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

