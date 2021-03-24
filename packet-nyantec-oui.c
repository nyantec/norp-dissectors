#include "config.h"

#include "packet-nyantec-oui.h"

#include <epan/packet.h>

value_string const nyantec_pid_vals[] = {
	{ 1528, "Not Only a Routeing Protocol" },
	{ 0, NULL }
};
