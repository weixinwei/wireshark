/* packet-ceph2.c
 * Routines for Ceph MSGR2 dissection
 * Copyright 2020, Xinwei Wei <xinweiwei90@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>

#include "packet-ceph.h"

void proto_reg_handoff_ceph2(void);
void proto_register_ceph2(void);

static dissector_handle_t ceph2_handle;

/* See ceph:/doc/dev/msgr2.rst
 */

/* Initialize the protocol and registered fields */
static int proto_ceph2					= -1;
static int hf_filter_data				= -1;
static int hf_banner_features_supported			= -1;
static int hf_banner_features_required			= -1;
static int hf_node_type					= -1;
static int hf_identity					= -1;
static int hf_tag					= -1;

/* Initialize the subtree pointers */
static gint ett_ceph					= -1;
static gint ett_filter_data				= -1;

static const guint8 *C_BANNER_V2_PREFIX = (const guint8*)"ceph v2\n";

#define C_BANNER_V2_SIZE_MIN		8
#define C_SIZE_MIN			8
#define C_BANNER_V2_FEATURES_SIZE	2
#define C_PREAMBLE_BLOCK_SIZE		32
#define C_EPILOGUE_PLAIN_BLOCK_SIZE	17

/** Message V2 Tags */
#define c_tag_strings_VALUE_STRING_LIST(V) \
	V(C_TAG_HELLO,			0x01, "client->server and server->client") \
	V(C_TAG_AUTH_REQUEST,		0x02, "client->server") \
	V(C_TAG_AUTH_BAD_METHOD,	0x03, "server -> client: reject client-selected auth method") \
	V(C_TAG_AUTH_REPLY_MORE,	0x04, "server->client") \
	V(C_TAG_AUTH_REQUEST_MORE,	0x05, "client->server") \
	V(C_TAG_AUTH_DONE,		0x06, "server->client") \
	V(C_TAG_AUTH_SIGNATURE,		0x07, "") \
	V(C_TAG_CLIENT_IDENT,		0x08, "client->server: identify ourselves") \
	V(C_TAG_SERVER_IDENT,		0x09, "server->client: accept client ident and identify server") \
	V(C_TAG_IDENT_MISSING_FEATURES,	0x0A, "server->client: complain about a TAG_IDENT with too few features") \
	V(C_TAG_SESSION_RECONNECT,	0x0B, "client->server: reconnect to an established session") \
	V(C_TAG_SESSION_RESET,		0x0C, "server only: ask client to reset session") \
	V(C_TAG_SESSION_RETRY,		0x0D, "server only: fail reconnect due to stale connect_seq") \
	V(C_TAG_SESSION_RETRY_GLOBAL,	0x0E, "server only: fail reconnect due to stale global_seq") \
	V(C_TAG_SESSION_RECONNECT_OK,	0x0F, "server->client: acknowledge a reconnect attempt") \
	V(C_TAG_WAIT, 			0x10, "server only: fail reconnect due to connect race") \
	V(C_TAG_MESSAGE, 		0x11, "message") \
	V(C_TAG_KEEPALIVE2, 		0x12, "keepalive2") \
	V(C_TAG_KEEPALIVE2_ACK, 	0x13, "keepalive2 reply") \
	V(C_TAG_ACK, 			0x14, "message ack")

VALUE_STRING_ENUM(c_tag_strings);
VALUE_STRING_ARRAY(c_tag_strings);
static value_string_ext c_tag_strings_ext = VALUE_STRING_EXT_INIT(c_tag_strings);

/** Do the connection initiation dance.
 *
 * This handles the data that is sent before the protocol is actually started.
 */
static
guint c_dissect_new(proto_tree *tree, gint is_client,
		    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	if (tvb_memeql(tvb, off, C_BANNER_V2_PREFIX, C_BANNER_V2_SIZE_MIN) != 0)
		return C_INVALID;

	off += C_BANNER_V2_SIZE_MIN + 2;

	proto_tree_add_item(tree, hf_banner_features_supported, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_banner_features_required, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	c_set_type(data, "Connect");

	/* 1. client send banner -> server
	 * 2. server send banner -> client
	 * 3. client send hello -> server
	 * 4. server send hello -> client
	 */
	if (is_client)
	{
		data->convd->server.state2 = C_STATE2_HANDSHAKE;
	}
	else
	{
		data->convd->client.state2 = C_STATE2_MSG;
		data->convd->server.state2 = C_STATE2_MSG;
	}

	return off;
}

typedef struct _c_preamble_block {
	c_tag tag;
	guint8 num_segments;
	guint32 crc;
} c_preamble_block;

static
guint c_dissect_preamble_block(proto_tree *tree _U_, c_preamble_block *out,
			       tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	/* ceph:/src/msg/async/frames_v2.h
	 *
	 * struct preamble_block_t {
	 * __u8 tag;
	 * __u8 num_segments;
	 * std::array<segment_t, MAX_NUM_SEGMENTS> segments;
	 * __u8 _reserved[2];
	 * ceph_le32 crc;
	 * } __attribute__((packed));
	 */

	c_preamble_block p;

	p.tag = tvb_get_guint8(tvb, off);
	off += 1;

	p.num_segments = tvb_get_guint8(tvb, off);
	off += 1;

	/* skip segments */
	off += 24;

	/* skip _reserved */
	off += 2;

	p.crc = tvb_get_letohl(tvb, off);
	off += 4;

	if (out) *out = p;

	return off;
}

typedef struct _c_epilogue_plain_block {
	guint8 late_flags;
} c_epilogue_plain_block;

static
guint c_dissect_epilogue_plain_block(proto_tree *tree _U_, c_epilogue_plain_block *out,
				     tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	/* ceph:/src/msg/async/frames_v2.h
	 *
	 * struct epilogue_plain_block_t {
	 * __u8 late_flags;
	 * std::array<ceph_le32, MAX_NUM_SEGMENTS> crc_values;
	 * } __attribute__((packed));
	 */

	c_epilogue_plain_block p;

	p.late_flags = tvb_get_guint8(tvb, off);
	off += 1;

	/* skip crc_values */
	off += 16;

	if (out) *out = p;

	return off;
}

static
guint c_dissect_hello(proto_tree *tree,
		      tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	/* ceph:/src/msg/async/ProtocolV2.cc
	 * ProtocolV2::handle_hello
	 */

	c_node_type type;
	char *type_str;

	c_set_type(data, "Hello");

	type = (c_node_type)tvb_get_guint8(tvb, off);
	type_str = c_node_type_string(type);
	proto_tree_add_item(tree, hf_node_type,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	off = c_dissect_entityaddr(tree, hf_identity, NULL, tvb, off, data);

	return off;
}

/* Dissect a MSGR2 message.
 *
 * MSGR2 is Ceph's outer message protocol.
 */
static
guint c_dissect_msgr2(proto_tree *tree,
		      tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	guint unknowntagcount = 1;
	c_preamble_block p;

	ti = proto_tree_add_item(tree, hf_tag, tvb, off, 1, ENC_LITTLE_ENDIAN);
	off = c_dissect_preamble_block(tree, &p, tvb, off, data);

	switch(p.tag)
	{
	case C_TAG_HELLO:
		off = c_dissect_hello(tree, tvb, off, data);
		break;
	case C_TAG_MESSAGE:
		off = c_dissect_msg(tree, tvb, off, data);
		break;
	default:
		break;
	}

	off = c_dissect_epilogue_plain_block(tree, NULL, tvb, off, data);
}

/* Dissect a Protocol Data Unit
 */
static
guint c_dissect_pdu(proto_tree *root,
		    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *tif;
	proto_tree *tree, *tree_filter;

	ti = proto_tree_add_item(root, proto_ceph2, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);

	data->item_root = ti;

	tif = proto_tree_add_item(tree, hf_filter_data, tvb, off, -1, ENC_NA);
	tree_filter = proto_item_add_subtree(tif, ett_filter_data);

	if (data->convd->server.state2 == C_STATE2_HANDSHAKE)
	{
		off = c_dissect_new(tree, 0, tvb, off, data);
	}
	else if (data->convd->client.state2 == C_STATE2_HANDSHAKE)
	{
		off = c_dissect_new(tree, 1, tvb, off, data);
	}
	else
	{
		off = c_dissect_msgr2(tree, tvb, off, data);
	}
	
	if (tree_filter) {
		proto_item_set_end(tif, tvb, off);
	}

	proto_item_set_end(ti,	tvb, off);

	return off;
}

static
guint c_pdu_end(tvbuff_t *tvb, packet_info *pinfo, guint off, c_pkt_data *data)
{
	c_inet	af;

	if (data->convd->client.state2 == C_STATE2_HANDSHAKE)
	{
		if (!tvb_bytes_exist(tvb, off, C_BANNER_V2_SIZE_MIN))
			return C_NEEDMORE;

		copy_address_wmem(wmem_file_scope(), &data->convd->client.addr, &pinfo->src);
		data->convd->client.port = pinfo->srcport;
		data->src = &data->convd->client;
	}
	else if (data->convd->server.state2 == C_STATE2_HANDSHAKE)
	{
		if (!tvb_bytes_exist(tvb, off, C_BANNER_V2_SIZE_MIN))
			return C_NEEDMORE;

		copy_address_wmem(wmem_file_scope(), &data->convd->server.addr, &pinfo->dst);
		data->convd->server.port = pinfo->destport;
		data->dst = &data->convd->server;
	}
	else
	{
		/* check min size of packet */
		if (!tvb_bytes_exist(tvb, off, C_PREAMBLE_BLOCK_SIZE))
			return C_NEEDMORE;

		/* do not care port */
		if (data->convd->client.port == 0xFFFF) {
			copy_address_wmem(wmem_file_scope(), &data->convd->client.addr, &pinfo->src);
			data->convd->client.port = pinfo->srcport;
			copy_address_wmem(wmem_file_scope(), &data->convd->server.addr, &pinfo->dst);
			data->convd->server.port = pinfo->destport;
			data->src = &data->convd->client;
			data->dst = &data->convd->server;
		}
	}

	switch(data->convd->client.state2)
	{
	case C_STATE2_HANDSHAKE:
		if (!tvb_bytes_exist(tvb, off+C_BANNER_V2_SIZE_MIN, C_BANNER_V2_FEATURES_SIZE))
			return C_NEEDMORE;
		return off + C_BANNER_V2_SIZE_MIN + C_BANNER_V2_FEATURES_SIZE
			   + tvb_get_letohs(tvb, off+C_BANNER_V2_SIZE_MIN);
	default:
		break;
	}
}

static
int dissect_ceph2(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, void *pdata _U_, gboolean handshake_of_ceph)
{
	guint off, offt, offt2;
	c_pkt_data data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ceph2");
	col_clear(pinfo->cinfo, COL_INFO);

	off = 0;
	while (off < tvb_reported_length(tvb))
	{
		c_pkt_data_init(&data, pinfo, proto_ceph2, off);

		/*
			If this is the handshake packet of ceph we captured, that is
			to say, we got a complete ceph tcp-stream(existing C_BANNER_V2_PREFIX),
			we can follow the previous logic(set state to C_STATE2_HANDSHAKE).
			Otherwise, we should set state to C_STATE2_MSG, thus goto
			c_dissect_msgr2() to dissect ceph msgr2.
		*/
		if (data.convd->new_conversation)
		{
			if (handshake_of_ceph)
			{
				data.convd->client.state2 = C_STATE2_HANDSHAKE;
			}
			else
			{
				data.convd->client.state2 = C_STATE2_MSG;
				data.convd->server.state2 = C_STATE2_MSG;
			}
		}

		/* Save snapshot before dissection changes it. */
		/*
			If some data has already been dissected in this frame we *must*
			save the state so we can remember that the rest of the frame is
			an incomplete PDU.
		*/
		if (off)
			c_pkt_data_save(&data, pinfo, proto_ceph2, off);

		offt = c_pdu_end(tvb, pinfo, off, &data);
		if (offt == C_INVALID)
		{
			return 0;
		}
		if (offt == C_NEEDMORE) /* Need more data to determine PDU length. */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len	= DESEGMENT_ONE_MORE_SEGMENT;
			return 1;
		}
		if (offt > tvb_reported_length(tvb)) /* Know PDU length, get rest */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len	= offt - tvb_reported_length(tvb);
			return 1;
		}

		/*
			If we didn't save above, save now.  This is a complete PDU so
			we need to save the state.
		*/
		if (!off)
			c_pkt_data_save(&data, pinfo, proto_ceph2, off);

		col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");
		col_set_fence(pinfo->cinfo, COL_INFO);

		offt2 = c_dissect_pdu(tree, tvb, off, &data);
		if (!offt2) return 0;
		DISSECTOR_ASSERT_CMPINT(offt2, ==, offt);

		off = offt;
	}

	return off; /* Perfect Fit. */
}

/** An old style dissector proxy.
 *
 * Proxies the old style dissector interface to the new style.
 */
static
int dissect_ceph2_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	dissect_ceph2(tvb, pinfo, tree, data, FALSE);
	return tvb_captured_length(tvb);
}

static guint32 ceph_mon_port_msgr2	= 3300;

static
gboolean dissect_ceph2_heur(tvbuff_t *tvb, packet_info *pinfo,
			    proto_tree *tree, void *data)
{
	return FALSE; /* TODO: disable ceph msgr2 */

	conversation_t *conv;
	gint has_ceph2_banner = 0; /* exist tcp connection banner */
	gint in_ceph2_port_range = 0; /* in ceph bind port range */
	guint32 srcport = pinfo->srcport; /* tcp src port */
	guint32 dstport = pinfo->destport; /* tcp dst port */

	has_ceph2_banner = tvb_memeql(tvb, 0, C_BANNER_V2_PREFIX, C_BANNER_V2_SIZE_MIN) == 0;

	in_ceph2_port_range = (srcport == ceph_mon_port_msgr2 ||
			       dstport == ceph_mon_port_msgr2 ||
			       (srcport >= ceph_ms_bind_port_min &&
			       srcport <= ceph_ms_bind_port_max) ||
			       (dstport >= ceph_ms_bind_port_min &&
			       dstport <= ceph_ms_bind_port_max));

	if (in_ceph2_port_range == 0 && has_ceph2_banner == 0) return FALSE;

	/*** It's ours! ***/

	conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
	conversation_set_dissector(conv, ceph2_handle);

	dissect_ceph2(tvb, pinfo, tree, data, has_ceph2_banner);
	return TRUE;
}

/* Register the protocol with Wireshark.
 */
void
proto_register_ceph2(void)
{
	expert_module_t *expert_ceph2;

	static hf_register_info hf[] = {
		{ &hf_filter_data, {
			"Filter Data", "ceph.filter",
			FT_NONE, BASE_NONE, NULL, 0,
			"A bunch of properties for convenient filtering.", HFILL
		} },
		{ &hf_banner_features_supported, {
			"Features Supported", "ceph.banner.features_supported",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_banner_features_required, {
			"Features Required", "ceph.banner.features_required",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_node_type, {
			"Source Node Type", "ceph.node_type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_strings), 0,
			"The type of source node.", HFILL
		} },
		{ &hf_identity, {
			"Identity", "ceph.identity",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_tag, {
			"Tag", "ceph.tag",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &c_tag_strings_ext, 0,
			NULL, HFILL
		} },
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
		&ett_filter_data,
	};

	/* Expert info items. */
	static ei_register_info ei[] = {
	};

	/* Register the protocol name and description */
	proto_ceph2 = proto_register_protocol("Ceph2", "Ceph2", "ceph2");

	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ceph2 = expert_register_protocol(proto_ceph2);
	expert_register_field_array(expert_ceph2, ei, array_length(ei));
}

void
proto_reg_handoff_ceph2(void)
{
	ceph2_handle = create_dissector_handle(dissect_ceph2_old, proto_ceph2);

	heur_dissector_add("tcp", dissect_ceph2_heur, "Ceph2 over TCP", "ceph2_tcp", proto_ceph2, HEURISTIC_ENABLE);
}