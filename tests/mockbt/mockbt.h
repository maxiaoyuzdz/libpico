#include <picobt/bt.h>

typedef struct {
	bt_err_t (*bt_connect_to_port)(const bt_addr_t *address, unsigned char port, bt_socket_t *sock);
	bt_err_t (*bt_accept)(bt_socket_t const * listener, bt_socket_t * sock);
	bt_err_t (*bt_listen)(bt_socket_t * listener);
	uint8_t (*bt_get_socket_channel)(bt_socket_t sock);
	bt_err_t (*bt_bind_to_channel)(bt_socket_t * listener, uint8_t channel);
	int (*bt_is_present)();
	bt_err_t (*bt_register_service)(bt_uuid_t const * service, char const * service_name, bt_socket_t *sock);
	bt_err_t (*bt_bind)(bt_socket_t * listener);
	bt_err_t (*bt_get_device_name)(bt_addr_t * addr);
	bt_err_t (*bt_set_timeout)(bt_socket_t *sock, int duration);
	void (*bt_addr_to_str_compact)(const bt_addr_t *addr, char *str);
	bt_err_t (*bt_str_compact_to_addr)(const char *str, bt_addr_t *addr);
} BTFunctions;

extern BTFunctions bt_funcs;

