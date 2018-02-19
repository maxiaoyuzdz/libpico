AUTOMAKE_OPTIONS = subdir-objects

TESTS = test_base64 test_buffer test_cryptosupport test_sigmaverifier test_json test_users test_auth test_displayqr test_continuous test_beacons

check_PROGRAMS = $(TESTS)
AM_CFLAGS = -Wall -Werror -Wno-unused-command-line-argument -Wno-c11-extensions -Wno-typedef-redefinition -I/usr/local/opt/openssl/include -I"../include" -pthread @CHECK_CFLAGS@
LDADD = ../libpico.la -L/usr/local/opt/openssl/lib -lssl -lcrypto -lz @CHECK_LIBS@ @PICOLIB_LIBS@



___libpico_a_CFLAGS = -std=gnu99 -fPIC -Wall -Werror -Wno-c11-extensions -Wno-typedef-redefinition -I/usr/local/opt/openssl/include -I"../include" @PICOBT_CFLAGS@


.PHONY: check-valgrind ;
check-valgrind: $(TESTS)
	@for test in $$(echo $(TESTS) | sed 's/tests\//tests\/.libs\//g') ; do \
		CK_FORK=no $(VALGRIND) --error-exitcode=1 --leak-resolution=low --quiet \
		--leak-check=full --show-possibly-lost=no --suppressions=valgrind.suppressions .libs/lt-$${test} ; \
	done
