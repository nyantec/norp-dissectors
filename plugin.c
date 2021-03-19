#include "config.h"

#include <epan/proto.h>

extern void proto_register_norp();

extern void proto_reg_handoff_norp();

gchar const plugin_version[] = PACKAGE_VERSION;
gchar const plugin_release[] = WIRESHARK_VERSION_RELEASE;
int const plugin_want_major = WIRESHARK_VERSION_MAJOR;
int const plugin_want_minor = WIRESHARK_VERSION_MINOR;

static proto_plugin plugin[] = {
	{
		.register_protoinfo = proto_register_norp,
		.register_handoff = proto_reg_handoff_norp,
	},
};

void plugin_register() {
	for (size_t i = 0; i < (sizeof plugin / sizeof *plugin); ++i) {
		proto_register_plugin(plugin + i);
	}
}
