#include "config.h"

#include "packet-norp.h"

#include <stdbool.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/expert.h>

static int dissect_norp(tvbuff_t *, packet_info *, proto_tree *, void *);

static value_string const coverage_names[] = {
	{ 0, "NORP Container" },
	{ 1, "Layer 4 Header" },
	{ 2, "Layer 3 Header" },
	{ 3, "Layer 2 Header" },
	{ 0, NULL }
};

static int proto_norp = -1;

static int hf_norp_version = -1;
static int hf_norp_coverage = -1;
static int hf_norp_selector = -1;
static int hf_norp_authenticator = -1;

static gint ett_norp = -1;

static expert_field ei_norp_invalid_container_length = EI_INIT;
static expert_field ei_norp_empty_container = EI_INIT;
static expert_field ei_norp_invalid_container_alignment = EI_INIT;
static expert_field ei_norp_unknown_version = EI_INIT;
static expert_field ei_norp_reserved_nonzero = EI_INIT;
static expert_field ei_norp_invalid_record_length = EI_INIT;
static expert_field ei_norp_unknown_record_type = EI_INIT;
static expert_field ei_norp_invalid_ancillary_length = EI_INIT;
static expert_field ei_norp_nonzero_external_padding = EI_INIT;
static expert_field ei_norp_nonzero_internal_padding = EI_INIT;
static expert_field ei_norp_nonzero_ancillary_padding = EI_INIT;

void proto_register_norp() {
	static hf_register_info hf[] = {
		{
			&hf_norp_version, {
				"Version", "norp.version",
				FT_UINT8, BASE_DEC,
				NULL, NORP_C_MASK_VERSION,
				"Protocol version", HFILL
			}
		}, {
			&hf_norp_coverage, {
				"Coverage", "norp.container.covg",
				FT_UINT8, BASE_DEC,
				&coverage_names, NORP_C_MASK_COVERAGE,
				"Container authenticator coverage", HFILL
			}
		}, {
			&hf_norp_selector, {
				"Key selector", "norp.container.key",
				FT_BYTES, BASE_NONE,
				NULL, 0,
				"Container group key selector", HFILL
			}
		}, {
			&hf_norp_authenticator, {
				"Authenticator", "norp.container.auth",
				FT_BYTES, BASE_NONE,
				NULL, 0,
				"Container authenticator", HFILL
			}
		}
	};

	static gint *ett[] = {
		&ett_norp
	};

	static ei_register_info ei[] = {
		{
			&ei_norp_invalid_container_length, {
				"norp.invalid_container_length", PI_MALFORMED, PI_ERROR, "Invalid container length", EXPFILL
			}
		}, {
			&ei_norp_empty_container, {
				"norp.empty_container", PI_PROTOCOL, PI_WARN, "Empty container", EXPFILL
			}
		}, {
			&ei_norp_invalid_container_alignment, {
				"norp.invalid_container_alignment", PI_MALFORMED, PI_WARN, "Invalid container trailer alignment", EXPFILL
			}
		}, {
			&ei_norp_unknown_version, {
				"norp.invalid_version", PI_PROTOCOL, PI_ERROR, "Unknown protocol version", EXPFILL
			}
		}, {
			&ei_norp_reserved_nonzero, {
				"norp.reserved_nonzero", PI_PROTOCOL, PI_WARN, "Non‐zero reserved field", EXPFILL
			}
		}, {
			&ei_norp_invalid_record_length, {
				"norp.invalid_record_length", PI_MALFORMED, PI_ERROR, "Invalid record length", EXPFILL
			}
		}, {
			&ei_norp_unknown_record_type, {
				"norp.unknown_record_type", PI_PROTOCOL, PI_ERROR, "Unknown record type", EXPFILL
			}
		}, {
			&ei_norp_invalid_ancillary_length, {
				"norp.invalid_ancillary_length", PI_MALFORMED, PI_ERROR, "Invalid ancillary data length", EXPFILL
			}
		}, {
			&ei_norp_nonzero_external_padding, {
				"norp.nonzero_external_padding", PI_PROTOCOL, PI_WARN, "Non‐zero external record padding", EXPFILL
			}
		}, {
			&ei_norp_nonzero_internal_padding, {
				"norp.nonzero_internal_padding", PI_PROTOCOL, PI_WARN, "Non‐zero internal padding", EXPFILL
			}
		}, {
			&ei_norp_nonzero_ancillary_padding, {
				"norp.nonzero_ancillary_padding", PI_PROTOCOL, PI_WARN, "Non‐zero ancillary data padding", EXPFILL
			}
		}
	};

	proto_norp = proto_register_protocol("Not Only a Routeing Protocol", "NORP", "norp");
	proto_register_field_array(proto_norp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_module_t *expert_norp = expert_register_protocol(proto_norp);
	expert_register_field_array(expert_norp, ei, array_length(ei));
}

void proto_reg_handoff_norp() {
	dissector_handle_t norp_handle = create_dissector_handle(dissect_norp, proto_norp);

	dissector_add_uint("ieee802a.nyantec_pid", NORP_PORT, norp_handle);
	dissector_add_uint("llc.nyantec_pid", NORP_PORT, norp_handle);
	dissector_add_uint("ip.proto", NORP_PROTO, norp_handle);
	dissector_add_uint("udp.port", NORP_PORT, norp_handle);
	dissector_add_uint("sctp.port", NORP_PORT, norp_handle);
}

static size_t align(size_t offset, size_t alignment) {
	return offset + ((alignment - (offset % alignment)) % alignment);
}

static int dissect_norp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NORP Container");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_norp, tvb, 0, -1, ENC_NA);
	proto_tree *norp_tree = proto_item_add_subtree(ti, ett_norp);

	size_t const plen = tvb_captured_length(tvb);

	if (plen < NORP_C_HEADER + NORP_C_TRAILER) {
		expert_add_info(pinfo, ti, &ei_norp_invalid_container_length);
		return 0;
	} else if (plen == NORP_C_HEADER + NORP_C_TRAILER) {
		expert_add_info(pinfo, ti, &ei_norp_empty_container);
	}

	if (plen % NORP_C_ALIGN != 0) {
		expert_add_info(pinfo, ti, &ei_norp_invalid_container_alignment);
	}

	uint8_t const c0 = tvb_get_guint8(tvb, NORP_C_OFF_HEAD);

	proto_tree_add_item(norp_tree, hf_norp_version, tvb,
		NORP_C_OFF_HEAD, NORP_C_LEN_HEAD, NORP_ENC);
	if ((c0 & NORP_C_MASK_VERSION) >> 4 != NORP_VERSION) {
		expert_add_info(pinfo, ti, &ei_norp_unknown_version);
		return NORP_C_OFF_HEAD + NORP_C_LEN_HEAD;
	}

	if ((c0 & NORP_C_MASK_RESERVED) != 0) {
		expert_add_info(pinfo, ti, &ei_norp_reserved_nonzero);
	}

	proto_tree_add_item(norp_tree, hf_norp_coverage, tvb,
		NORP_C_OFF_HEAD, NORP_C_LEN_HEAD, NORP_ENC);

	proto_tree_add_item(norp_tree, hf_norp_selector, tvb,
		NORP_C_OFF_SELECTOR, NORP_C_LEN_SELECTOR, NORP_ENC);

	size_t const trailer = plen - NORP_C_TRAILER;
	proto_tree_add_item(norp_tree, hf_norp_authenticator, tvb,
		trailer + NORP_C_OFF_AUTHENTICATOR, NORP_C_LEN_AUTHENTICATOR, NORP_ENC);

	return plen;
}
