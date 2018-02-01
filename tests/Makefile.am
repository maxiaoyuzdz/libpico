AUTOMAKE_OPTIONS = subdir-objects

TESTS = test_base64 test_buffer test_cryptosupport test_sigmaverifier test_channel test_json test_users test_auth test_displayqr test_continuous test_beacons test_fsm test_messages

noinst_LTLIBRARIES   = lib_mockbt.la
lib_mockbt_la_SOURCES = \
	mockbt/mockbt.c 
lib_mockbt_la_CFLAGS  = $(AM_CFLAGS) @PICOBT_CFLAGS@

check_PROGRAMS = $(TESTS)
AM_CFLAGS = -Wall -Werror -I"../include" -pthread @CHECK_CFLAGS@
LDADD = ../libpico.la .libs/lib_mockbt.la @CHECK_LIBS@ @PICOLIB_LIBS@


.PHONY: check-valgrind ;
check-valgrind: $(TESTS)
	@for test in $$(echo $(TESTS) | sed 's/tests\//tests\/.libs\//g') ; do \
		CK_FORK=no $(VALGRIND) --error-exitcode=1 --leak-resolution=low --quiet \
		--leak-check=full --show-possibly-lost=no --suppressions=valgrind.suppressions .libs/lt-$${test} ; \
	done
