#include "config.h"

#include "packet-nyantec-oui.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-ieee802a.h>

static int hf_ieee802a_nyantec_pid = -1;

void proto_register_ieee802a_nyantec() {
	static hf_register_info hf[] = {
		{
			&hf_ieee802a_nyantec_pid, {
				"PID", "ieee802a.nyantec_pid",
				FT_UINT16, BASE_HEX,
				VALS(nyantec_pid_vals), 0,
				"Protocol ID", HFILL
			}
		}
	};

	ieee802a_add_oui(OUI_NYANTEC, "ieee802a.nyantec_pid", "IEEE 802a nyantec OUI PID", hf, -1);
}
