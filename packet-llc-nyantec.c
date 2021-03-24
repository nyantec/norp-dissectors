#include "config.h"

#include "packet-nyantec-oui.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-llc.h>

static int hf_llc_nyantec_pid = -1;

void proto_register_llc_nyantec() {
	static hf_register_info hf[] = {
		{
			&hf_llc_nyantec_pid, {
				"PID", "llc.nyantec_pid",
				FT_UINT16, BASE_HEX,
				VALS(nyantec_pid_vals), 0,
				"Protocol ID", HFILL
			}
		}
	};

	llc_add_oui(OUI_NYANTEC, "llc.nyantec_pid", "LLC nyantec OUI PID", hf, -1);
}
