#ifndef PACKET_NORP_H
#define PACKET_NORP_H

#include <stdint.h>

#include <epan/packet.h>

#define NORP_ENC ENC_BIG_ENDIAN

#define NORP_PROTO UINT8_C(0xfe)
#define NORP_PORT UINT16_C(1528)

#define NORP_VERSION 2u

#define NORP_C_HEADER 16u
#define NORP_C_TRAILER 8u
#define NORP_C_ALIGN 8u

#define NORP_C_OFF_HEAD 0u
#define NORP_C_OFF_SELECTOR 1u
#define NORP_C_OFF_AUTHENTICATOR 0u

#define NORP_C_LEN_HEAD 1u
#define NORP_C_LEN_SELECTOR 15u
#define NORP_C_LEN_AUTHENTICATOR 8u

#define NORP_C_MASK_VERSION UINT8_C(0xf0)
#define NORP_C_MASK_RESERVED UINT8_C(0x0c)
#define NORP_C_MASK_COVERAGE UINT8_C(0x03)

#endif
