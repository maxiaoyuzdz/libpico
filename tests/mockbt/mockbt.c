#if HAVE_CONFIG_H
#include "pico/config.h"
#endif

#ifdef HAVE_LIBPICOBT // Only build if Bluetooth is present

#include "mockbt.h"
#include <stdlib.h>

BTFunctions bt_funcs = {
	.bt_connect_to_port = NULL,
	.bt_accept = NULL,
	.bt_listen = NULL,
	.bt_get_socket_channel = NULL,
	.bt_bind_to_channel = NULL,
	.bt_is_present = NULL,
	.bt_register_service = NULL,
	.bt_bind = NULL,
	.bt_get_device_name = NULL,
	.bt_set_timeout = NULL,
	.bt_addr_to_str_compact = NULL,
	.bt_str_compact_to_addr = NULL,
};

#define FUNCTION_BODY(name, ...)\
{ \
	if (!bt_funcs.name) { \
		printf("UNEXPECTED NULL Function pointer %s\n", #name); \
	} \
	return bt_funcs.name (__VA_ARGS__); \
}

#define FUNCTION0(ret, mockedfunc) \
	ret mockedfunc () \
	FUNCTION_BODY(mockedfunc)

#define FUNCTION1(ret, mockedfunc, A1) \
	ret mockedfunc (A1 _1) \
	FUNCTION_BODY(mockedfunc, _1)

#define FUNCTION2(ret, mockedfunc, A1, A2) \
	ret mockedfunc (A1 _1, A2 _2) \
	FUNCTION_BODY(mockedfunc, _1, _2)

#define FUNCTION3(ret, mockedfunc, A1, A2, A3) \
	ret mockedfunc (A1 _1, A2 _2, A3 _3) \
	FUNCTION_BODY(mockedfunc, _1, _2, _3)

FUNCTION3(bt_err_t, bt_connect_to_port, const bt_addr_t*, unsigned char, bt_socket_t*);
FUNCTION2(bt_err_t, bt_accept, bt_socket_t const*, bt_socket_t*);
FUNCTION1(bt_err_t, bt_listen, bt_socket_t*);
FUNCTION1(uint8_t, bt_get_socket_channel, bt_socket_t);
FUNCTION2(bt_err_t, bt_bind_to_channel, bt_socket_t*, uint8_t);
FUNCTION0(int, bt_is_present);
FUNCTION3(bt_err_t, bt_register_service, bt_uuid_t const*, char const*, bt_socket_t*);
FUNCTION1(bt_err_t, bt_bind, bt_socket_t*);
FUNCTION1(bt_err_t, bt_get_device_name, bt_addr_t*);
FUNCTION2(bt_err_t, bt_set_timeout, bt_socket_t*, int);
FUNCTION2(void, bt_addr_to_str_compact, const bt_addr_t*, char*);
FUNCTION2(bt_err_t, bt_str_compact_to_addr, const char*, bt_addr_t*);

#endif // HAVE_LIBPICOBT // Only build if Bluetooth is present

