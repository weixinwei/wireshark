/* packet-ceph.h
 * Defines for Ceph MSGR1 dissection
 * Copyright 2014, Kevin Cox <kevincox@kevincox.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_CEPH_H__
#define __PACKET_CEPH_H__

#include <epan/proto.h>
#include <epan/wmem/wmem.h>

/* See ceph:/doc/dev/network-protocol.rst
 */

#define C_NEEDMORE      G_MAXUINT
#define C_INVALID       0

/** Feature Flags */
/* Transmuted from ceph:/src/include/ceph_features.h */
#define C_FEATURE_UID		       (1U <<  0)
#define C_FEATURE_NOSRCADDR	       (1U <<  1)
#define C_FEATURE_MONCLOCKCHECK	       (1U <<  2)
#define C_FEATURE_FLOCK		       (1U <<  3)
#define C_FEATURE_SUBSCRIBE2	       (1U <<  4)
#define C_FEATURE_MONNAMES	       (1U <<  5)
#define C_FEATURE_RECONNECT_SEQ	       (1U <<  6)
#define C_FEATURE_DIRLAYOUTHASH	       (1U <<  7)
#define C_FEATURE_OBJECTLOCATOR	       (1U <<  8)
#define C_FEATURE_PGID64	       (1U <<  9)
#define C_FEATURE_INCSUBOSDMAP	       (1U << 10)
#define C_FEATURE_PGPOOL3	       (1U << 11)
#define C_FEATURE_OSDREPLYMUX	       (1U << 12)
#define C_FEATURE_OSDENC	       (1U << 13)
#define C_FEATURE_OMAP		       (1U << 14)
#define C_FEATURE_MONENC	       (1U << 15)
#define C_FEATURE_QUERY_T	       (1U << 16)
#define C_FEATURE_INDEP_PG_MAP	       (1U << 17)
#define C_FEATURE_CRUSH_TUNABLES       (1U << 18)
#define C_FEATURE_CHUNKY_SCRUB	       (1U << 19)
#define C_FEATURE_MON_NULLROUTE	       (1U << 20)
#define C_FEATURE_MON_GV	       (1U << 21)
#define C_FEATURE_BACKFILL_RESERVATION (1U << 22)
#define C_FEATURE_MSG_AUTH	       (1U << 23)
#define C_FEATURE_RECOVERY_RESERVATION (1U << 24)
#define C_FEATURE_CRUSH_TUNABLES2      (1U << 25)
#define C_FEATURE_CREATEPOOLID	       (1U << 26)
#define C_FEATURE_REPLY_CREATE_INODE   (1U << 27)
#define C_FEATURE_OSD_HBMSGS	       (1U << 28)
#define C_FEATURE_MDSENC	       (1U << 29)
#define C_FEATURE_OSDHASHPSPOOL	       (1U << 30)
#define C_FEATURE_MON_SINGLE_PAXOS     (1U << 31)
#define C_FEATURE_OSD_SNAPMAPPER       (1U <<  0)
#define C_FEATURE_MON_SCRUB	       (1U <<  1)
#define C_FEATURE_OSD_PACKED_RECOVERY  (1U <<  2)
#define C_FEATURE_OSD_CACHEPOOL	       (1U <<  3)
#define C_FEATURE_CRUSH_V2	       (1U <<  4)
#define C_FEATURE_EXPORT_PEER	       (1U <<  5)
#define C_FEATURE_OSD_ERASURE_CODES    (1U <<  6)
#define C_FEATURE_OSD_TMAP2OMAP	       (1U <<  6)
#define C_FEATURE_OSDMAP_ENC	       (1U <<  7)
#define C_FEATURE_MDS_INLINE_DATA      (1U <<  8)
#define C_FEATURE_CRUSH_TUNABLES3      (1U <<  9)
#define C_FEATURE_OSD_PRIMARY_AFFINITY (1U <<  9)
#define C_FEATURE_MSGR_KEEPALIVE2      (1U << 10)
#define C_FEATURE_RESERVED	       (1U << 31)

/** Connect Message Flags */
#define C_FLAG_LOSSY	               (1U << 0)

#define C_PGPOOL_FLAG_HASHPSPOOL       (1U << 0) /* hash pg seed and pool together (instead of adding) */
#define C_PGPOOL_FLAG_FULL	       (1U << 1) /* pool is full */
#define C_PGPOOL_FLAG_FAKE_EC_POOL     (1U << 2) /* require ReplicatedPG to act like an EC pg */

/** Macros to create value_stings.
 *
 * These are a quick wrapper around the functions in value_string.h.  They
 * create an enum `base` with the given values, a `value_string base_strings[]`
 * and a function `const char `base_string(base val)` which gets the string
 * for a value.
 *
 * Additionally, C_MAKE_STRINGS_EXT creates a
 * `value_strings_ext base_strings_ext` and uses this for the `base_string`
 * lookup.
 *
 * @param base The root name.
 * @param chars The number of characters to use when displaying the value.
 *		this is generally 2*bytes.
 */
#define C_MAKE_STRINGS(base, chars) \
	typedef gint base; \
	VALUE_STRING_ENUM(base##_strings); \
	VALUE_STRING_ARRAY(base##_strings); \
	static const char *base##_string(base val) { \
		return val_to_str(val, base##_strings, "Unknown (0x0"#chars"X)"); \
	}

#define C_MAKE_STRINGS_EXT(base, chars) \
	typedef gint base; \
	VALUE_STRING_ENUM(base##_strings); \
	VALUE_STRING_ARRAY(base##_strings); \
	\
	static value_string_ext \
	base##_strings_ext = VALUE_STRING_EXT_INIT(base##_strings); \
	\
	static const char *base##_string(base val) { \
		return val_to_str_ext(val, &base##_strings_ext, "Unknown (0x0"#chars"X)"); \
	}

#define c_inet_strings_VALUE_STRING_LIST(V) \
	V(C_IPv4, 0x0002, "IPv4") \
	V(C_IPv6, 0x000A, "IPv6")

typedef guint16 c_inet;
VALUE_STRING_ENUM(c_inet_strings);
VALUE_STRING_ARRAY(c_inet_strings);

typedef gint c_tag;

/* Extracted from the Ceph tree.
 *
 * These are MSG_* constants for server <-> server (internal) messages. and
 * CEPH_MSG_* for client <-> server messages.  There is no functional
 * difference, just a naming convention.
 */
#define c_msg_type_strings_VALUE_STRING_LIST(V) \
	V(C_MSG_UNKNOWN,		     0x0000, "Unknown (0x0000)")		  \
											  \
	V(C_CEPH_MSG_SHUTDOWN,		     0x0001, "C_CEPH_MSG_SHUTDOWN")		  \
	V(C_CEPH_MSG_PING,		     0x0002, "C_CEPH_MSG_PING")			  \
	V(C_CEPH_MSG_MON_MAP,		     0x0004, "C_CEPH_MSG_MON_MAP")		  \
	V(C_CEPH_MSG_MON_GET_MAP,	     0x0005, "C_CEPH_MSG_MON_GET_MAP")		  \
	V(C_CEPH_MSG_STATFS,		     0x000D, "C_CEPH_MSG_STATFS")		  \
	V(C_CEPH_MSG_STATFS_REPLY,	     0x000E, "C_CEPH_MSG_STATFS_REPLY")		  \
	V(C_CEPH_MSG_MON_SUBSCRIBE,	     0x000F, "C_CEPH_MSG_MON_SUBSCRIBE")	  \
	V(C_CEPH_MSG_MON_SUBSCRIBE_ACK,	     0x0010, "C_CEPH_MSG_MON_SUBSCRIBE_ACK")	  \
	V(C_CEPH_MSG_AUTH,		     0x0011, "C_CEPH_MSG_AUTH")			  \
	V(C_CEPH_MSG_AUTH_REPLY,	     0x0012, "C_CEPH_MSG_AUTH_REPLY")		  \
	V(C_CEPH_MSG_MON_GET_VERSION,	     0x0013, "C_CEPH_MSG_MON_GET_VERSION")	  \
	V(C_CEPH_MSG_MON_GET_VERSION_REPLY,  0x0014, "C_CEPH_MSG_MON_GET_VERSION_REPLY")  \
	V(C_CEPH_MSG_MDS_MAP,		     0x0015, "C_CEPH_MSG_MDS_MAP")		  \
	V(C_CEPH_MSG_CLIENT_SESSION,	     0x0016, "C_CEPH_MSG_CLIENT_SESSION")	  \
	V(C_CEPH_MSG_CLIENT_RECONNECT,	     0x0017, "C_CEPH_MSG_CLIENT_RECONNECT")	  \
	V(C_CEPH_MSG_CLIENT_REQUEST,	     0x0018, "C_CEPH_MSG_CLIENT_REQUEST")	  \
	V(C_CEPH_MSG_CLIENT_REQUEST_FORWARD, 0x0019, "C_CEPH_MSG_CLIENT_REQUEST_FORWARD") \
	V(C_CEPH_MSG_CLIENT_REPLY,	     0x001A, "C_CEPH_MSG_CLIENT_REPLY")		  \
	V(C_MSG_PAXOS,			     0x0028, "C_MSG_PAXOS")			  \
	V(C_CEPH_MSG_OSD_MAP,		     0x0029, "C_CEPH_MSG_OSD_MAP")		  \
	V(C_CEPH_MSG_OSD_OP,		     0x002A, "C_CEPH_MSG_OSD_OP")		  \
	V(C_CEPH_MSG_OSD_OPREPLY,	     0x002B, "C_CEPH_MSG_OSD_OPREPLY")		  \
	V(C_CEPH_MSG_WATCH_NOTIFY,	     0x002C, "C_CEPH_MSG_WATCH_NOTIFY")		  \
	V(C_MSG_FORWARD,		     0x002E, "C_MSG_FORWARD")			  \
	V(C_MSG_ROUTE,			     0x002F, "C_MSG_ROUTE")			  \
	V(C_MSG_POOLOPREPLY,		     0x0030, "C_MSG_POOLOPREPLY")		  \
	V(C_MSG_POOLOP,			     0x0031, "C_MSG_POOLOP")			  \
	V(C_MSG_MON_COMMAND,		     0x0032, "C_MSG_MON_COMMAND")		  \
	V(C_MSG_MON_COMMAND_ACK,	     0x0033, "C_MSG_MON_COMMAND_ACK")		  \
	V(C_MSG_LOG,			     0x0034, "C_MSG_LOG")			  \
	V(C_MSG_LOGACK,			     0x0035, "C_MSG_LOGACK")			  \
	V(C_MSG_MON_OBSERVE,		     0x0036, "C_MSG_MON_OBSERVE")		  \
	V(C_MSG_MON_OBSERVE_NOTIFY,	     0x0037, "C_MSG_MON_OBSERVE_NOTIFY")	  \
	V(C_MSG_CLASS,			     0x0038, "C_MSG_CLASS")			  \
	V(C_MSG_CLASS_ACK,		     0x0039, "C_MSG_CLASS_ACK")			  \
	V(C_MSG_GETPOOLSTATS,		     0x003A, "C_MSG_GETPOOLSTATS")		  \
	V(C_MSG_GETPOOLSTATSREPLY,	     0x003B, "C_MSG_GETPOOLSTATSREPLY")		  \
	V(C_MSG_MON_GLOBAL_ID,		     0x003C, "C_MSG_MON_GLOBAL_ID")		  \
/*	V(C_CEPH_MSG_PRIO_LOW,		     0x0040, "C_CEPH_MSG_PRIO_LOW")		*/ \
	V(C_MSG_MON_SCRUB,		     0x0040, "C_MSG_MON_SCRUB")			  \
	V(C_MSG_MON_ELECTION,		     0x0041, "C_MSG_MON_ELECTION")		  \
	V(C_MSG_MON_PAXOS,		     0x0042, "C_MSG_MON_PAXOS")			  \
	V(C_MSG_MON_PROBE,		     0x0043, "C_MSG_MON_PROBE")			  \
	V(C_MSG_MON_JOIN,		     0x0044, "C_MSG_MON_JOIN")			  \
	V(C_MSG_MON_SYNC,		     0x0045, "C_MSG_MON_SYNC")			  \
	V(C_MSG_OSD_PING,		     0x0046, "C_MSG_OSD_PING")			  \
	V(C_MSG_OSD_BOOT,		     0x0047, "C_MSG_OSD_BOOT")			  \
	V(C_MSG_OSD_FAILURE,		     0x0048, "C_MSG_OSD_FAILURE")		  \
	V(C_MSG_OSD_ALIVE,		     0x0049, "C_MSG_OSD_ALIVE")			  \
	V(C_MSG_OSD_MARK_ME_DOWN,	     0x004A, "C_MSG_OSD_MARK_ME_DOWN")		  \
	V(C_MSG_OSD_SUBOP,		     0x004C, "C_MSG_OSD_SUBOP")			  \
	V(C_MSG_OSD_SUBOPREPLY,		     0x004D, "C_MSG_OSD_SUBOPREPLY")		  \
	V(C_MSG_OSD_PGTEMP,		     0x004E, "C_MSG_OSD_PGTEMP")		  \
	V(C_MSG_OSD_PG_NOTIFY,		     0x0050, "C_MSG_OSD_PG_NOTIFY")		  \
	V(C_MSG_OSD_PG_QUERY,		     0x0051, "C_MSG_OSD_PG_QUERY")		  \
	V(C_MSG_OSD_PG_SUMMARY,		     0x0052, "C_MSG_OSD_PG_SUMMARY")		  \
	V(C_MSG_OSD_PG_LOG,		     0x0053, "C_MSG_OSD_PG_LOG")		  \
	V(C_MSG_OSD_PG_REMOVE,		     0x0054, "C_MSG_OSD_PG_REMOVE")		  \
	V(C_MSG_OSD_PG_INFO,		     0x0055, "C_MSG_OSD_PG_INFO")		  \
	V(C_MSG_OSD_PG_TRIM,		     0x0056, "C_MSG_OSD_PG_TRIM")		  \
	V(C_MSG_PGSTATS,		     0x0057, "C_MSG_PGSTATS")			  \
	V(C_MSG_PGSTATSACK,		     0x0058, "C_MSG_PGSTATSACK")		  \
	V(C_MSG_OSD_PG_CREATE,		     0x0059, "C_MSG_OSD_PG_CREATE")		  \
	V(C_MSG_REMOVE_SNAPS,		     0x005A, "C_MSG_REMOVE_SNAPS")		  \
	V(C_MSG_OSD_SCRUB,		     0x005B, "C_MSG_OSD_SCRUB")			  \
	V(C_MSG_OSD_PG_MISSING,		     0x005C, "C_MSG_OSD_PG_MISSING")		  \
	V(C_MSG_OSD_REP_SCRUB,		     0x005D, "C_MSG_OSD_REP_SCRUB")		  \
	V(C_MSG_OSD_PG_SCAN,		     0x005E, "C_MSG_OSD_PG_SCAN")		  \
	V(C_MSG_OSD_PG_BACKFILL,	     0x005F, "C_MSG_OSD_PG_BACKFILL")		  \
	V(C_MSG_COMMAND,		     0x0061, "C_MSG_COMMAND")			  \
	V(C_MSG_COMMAND_REPLY,		     0x0062, "C_MSG_COMMAND_REPLY")		  \
	V(C_MSG_OSD_BACKFILL_RESERVE,	     0x0063, "C_MSG_OSD_BACKFILL_RESERVE")	  \
	V(C_MSG_MDS_BEACON,		     0x0064, "C_MSG_MDS_BEACON")		  \
	V(C_MSG_MDS_SLAVE_REQUEST,	     0x0065, "C_MSG_MDS_SLAVE_REQUEST")		  \
	V(C_MSG_MDS_TABLE_REQUEST,	     0x0066, "C_MSG_MDS_TABLE_REQUEST")		  \
	V(C_MSG_OSD_PG_PUSH,		     0x0069, "C_MSG_OSD_PG_PUSH")		  \
	V(C_MSG_OSD_PG_PULL,		     0x006A, "C_MSG_OSD_PG_PULL")		  \
	V(C_MSG_OSD_PG_PUSH_REPLY,	     0x006B, "C_MSG_OSD_PG_PUSH_REPLY")		  \
	V(C_MSG_OSD_EC_WRITE,		     0x006C, "C_MSG_OSD_EC_WRITE")		  \
	V(C_MSG_OSD_EC_WRITE_REPLY,	     0x006D, "C_MSG_OSD_EC_WRITE_REPLY")	  \
	V(C_MSG_OSD_EC_READ,		     0x006E, "C_MSG_OSD_EC_READ")		  \
	V(C_MSG_OSD_EC_READ_REPLY,	     0x006F, "C_MSG_OSD_EC_READ_REPLY")		  \
	V(C_MSG_OSD_PG_UPDATE_LOG_MISSING,   0x0072, "C_MSG_OSD_PG_UPDATE_LOG_MISSING")   \
	V(C_MSG_OSD_PG_UPDATE_LOG_MISSING_REPLY,0x0073, "C_MSG_OSD_PG_UPDATE_LOG_MISSING_REPLY") \
	V(C_CEPH_MSG_PRIO_DEFAULT,	     0x007F, "C_CEPH_MSG_PRIO_DEFAULT")		  \
	V(C_MSG_OSD_RECOVERY_RESERVE,	     0x0096, "C_MSG_OSD_RECOVERY_RESERVE")	  \
	V(C_CEPH_MSG_PRIO_HIGH,		     0x00C4, "C_CEPH_MSG_PRIO_HIGH")		  \
	V(C_CEPH_MSG_PRIO_HIGHEST,	     0x00FF, "C_CEPH_MSG_PRIO_HIGHEST")		  \
	V(C_MSG_MDS_RESOLVE,		     0x0200, "C_MSG_MDS_RESOLVE")		  \
	V(C_MSG_MDS_RESOLVEACK,		     0x0201, "C_MSG_MDS_RESOLVEACK")		  \
	V(C_MSG_MDS_CACHEREJOIN,	     0x0202, "C_MSG_MDS_CACHEREJOIN")		  \
	V(C_MSG_MDS_DISCOVER,		     0x0203, "C_MSG_MDS_DISCOVER")		  \
	V(C_MSG_MDS_DISCOVERREPLY,	     0x0204, "C_MSG_MDS_DISCOVERREPLY")		  \
	V(C_MSG_MDS_INODEUPDATE,	     0x0205, "C_MSG_MDS_INODEUPDATE")		  \
	V(C_MSG_MDS_DIRUPDATE,		     0x0206, "C_MSG_MDS_DIRUPDATE")		  \
	V(C_MSG_MDS_CACHEEXPIRE,	     0x0207, "C_MSG_MDS_CACHEEXPIRE")		  \
	V(C_MSG_MDS_DENTRYUNLINK,	     0x0208, "C_MSG_MDS_DENTRYUNLINK")		  \
	V(C_MSG_MDS_FRAGMENTNOTIFY,	     0x0209, "C_MSG_MDS_FRAGMENTNOTIFY")	  \
	V(C_MSG_MDS_OFFLOAD_TARGETS,	     0x020A, "C_MSG_MDS_OFFLOAD_TARGETS")	  \
	V(C_MSG_MDS_DENTRYLINK,		     0x020C, "C_MSG_MDS_DENTRYLINK")		  \
	V(C_MSG_MDS_FINDINO,		     0x020D, "C_MSG_MDS_FINDINO")		  \
	V(C_MSG_MDS_FINDINOREPLY,	     0x020E, "C_MSG_MDS_FINDINOREPLY")		  \
	V(C_MSG_MDS_OPENINO,		     0x020F, "C_MSG_MDS_OPENINO")		  \
	V(C_MSG_MDS_OPENINOREPLY,	     0x0210, "C_MSG_MDS_OPENINOREPLY")		  \
	V(C_MSG_MDS_LOCK,		     0x0300, "C_MSG_MDS_LOCK")			  \
	V(C_MSG_MDS_INODEFILECAPS,	     0x0301, "C_MSG_MDS_INODEFILECAPS")		  \
	V(C_CEPH_MSG_CLIENT_CAPS,	     0x0310, "C_CEPH_MSG_CLIENT_CAPS")		  \
	V(C_CEPH_MSG_CLIENT_LEASE,	     0x0311, "C_CEPH_MSG_CLIENT_LEASE")		  \
	V(C_CEPH_MSG_CLIENT_SNAP,	     0x0312, "C_CEPH_MSG_CLIENT_SNAP")		  \
	V(C_CEPH_MSG_CLIENT_CAPRELEASE,	     0x0313, "C_CEPH_MSG_CLIENT_CAPRELEASE")	  \
	V(C_MSG_MDS_EXPORTDIRDISCOVER,	     0x0449, "C_MSG_MDS_EXPORTDIRDISCOVER")	  \
	V(C_MSG_MDS_EXPORTDIRDISCOVERACK,    0x0450, "C_MSG_MDS_EXPORTDIRDISCOVERACK")	  \
	V(C_MSG_MDS_EXPORTDIRCANCEL,	     0x0451, "C_MSG_MDS_EXPORTDIRCANCEL")	  \
	V(C_MSG_MDS_EXPORTDIRPREP,	     0x0452, "C_MSG_MDS_EXPORTDIRPREP")		  \
	V(C_MSG_MDS_EXPORTDIRPREPACK,	     0x0453, "C_MSG_MDS_EXPORTDIRPREPACK")	  \
	V(C_MSG_MDS_EXPORTDIRWARNING,	     0x0454, "C_MSG_MDS_EXPORTDIRWARNING")	  \
	V(C_MSG_MDS_EXPORTDIRWARNINGACK,     0x0455, "C_MSG_MDS_EXPORTDIRWARNINGACK")	  \
	V(C_MSG_MDS_EXPORTDIR,		     0x0456, "C_MSG_MDS_EXPORTDIR")		  \
	V(C_MSG_MDS_EXPORTDIRACK,	     0x0457, "C_MSG_MDS_EXPORTDIRACK")		  \
	V(C_MSG_MDS_EXPORTDIRNOTIFY,	     0x0458, "C_MSG_MDS_EXPORTDIRNOTIFY")	  \
	V(C_MSG_MDS_EXPORTDIRNOTIFYACK,	     0x0459, "C_MSG_MDS_EXPORTDIRNOTIFYACK")	  \
	V(C_MSG_MDS_EXPORTDIRFINISH,	     0x0460, "C_MSG_MDS_EXPORTDIRFINISH")	  \
	V(C_MSG_MDS_EXPORTCAPS,		     0x0470, "C_MSG_MDS_EXPORTCAPS")		  \
	V(C_MSG_MDS_EXPORTCAPSACK,	     0x0471, "C_MSG_MDS_EXPORTCAPSACK")		  \
	V(C_MSG_MDS_HEARTBEAT,		     0x0500, "C_MSG_MDS_HEARTBEAT")		  \
	V(C_MSG_TIMECHECK,		     0x0600, "C_MSG_TIMECHECK")			  \
	V(C_MSG_MON_HEALTH,		     0x0601, "C_MSG_MON_HEALTH")		  \
	V(C_MSG_MGR_OPEN,		     0x0700, "C_MSG_MGR_OPEN")			  \
	V(C_MSG_MGR_CONFIGURE,		     0x0701, "C_MSG_MGR_CONFIGURE")		  \
	V(C_MSG_MGR_REPORT,		     0x0702, "C_MSG_MGR_REPORT")		  \
	V(C_MSG_MGR_BEACON,		     0x0703, "C_MSG_MGR_BEACON")		  \
	V(C_MSG_MGR_MAP,		     0x0704, "C_MSG_MGR_MAP")			  \
	V(C_MSG_MGR_DIGEST,		     0x0705, "C_MSG_MGR_DIGEST")		  \
	V(C_MSG_MON_MGR_REPORT,		     0x0706, "C_MSG_MON_MGR_REPORT")		  \
	V(C_MSG_SERVICE_MAP,		     0x0707, "C_MSG_SERVICE_MAP")		  \
	V(C_MSG_MGR_CLOSE,		     0x0708, "C_MSG_MGR_CLOSE")

C_MAKE_STRINGS_EXT(c_msg_type, 4)

#define c_osd_optype_strings_VALUE_STRING_LIST(V) \
	/*** Raw Codes ***/												\
	V(C_OSD_OP_TYPE_LOCK,  0x0100, "C_OSD_OP_TYPE_LOCK")								\
	V(C_OSD_OP_TYPE_DATA,  0x0200, "C_OSD_OP_TYPE_DATA")								\
	V(C_OSD_OP_TYPE_ATTR,  0x0300, "C_OSD_OP_TYPE_ATTR")								\
	V(C_OSD_OP_TYPE_EXEC,  0x0400, "C_OSD_OP_TYPE_EXEC")								\
	V(C_OSD_OP_TYPE_PG,    0x0500, "C_OSD_OP_TYPE_PG")								\
	V(C_OSD_OP_TYPE_MULTI, 0x0600, "C_OSD_OP_TYPE_MULTI") /* multiobject */						\
	V(C_OSD_OP_TYPE,       0x0f00, "C_OSD_OP_TYPE")									\
															\
	/*** Sorted by value, keep it that way. ***/									\
	V(C_OSD_OP_MODE_RD,	       0x1000,						 "C_OSD_OP_MODE_RD")		\
	V(C_OSD_OP_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x01, "C_OSD_OP_READ")		\
	V(C_OSD_OP_STAT,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x02, "C_OSD_OP_STAT")		\
	V(C_OSD_OP_MAPEXT,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x03, "C_OSD_OP_MAPEXT")		\
	V(C_OSD_OP_MASKTRUNC,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x04, "C_OSD_OP_MASKTRUNC")		\
	V(C_OSD_OP_SPARSE_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x05, "C_OSD_OP_SPARSE_READ")	\
	V(C_OSD_OP_NOTIFY,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x06, "C_OSD_OP_NOTIFY")		\
	V(C_OSD_OP_NOTIFY_ACK,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x07, "C_OSD_OP_NOTIFY_ACK")		\
	V(C_OSD_OP_ASSERT_VER,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x08, "C_OSD_OP_ASSERT_VER")		\
	V(C_OSD_OP_LIST_WATCHERS,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x09, "C_OSD_OP_LIST_WATCHERS")	\
	V(C_OSD_OP_LIST_SNAPS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0A, "C_OSD_OP_LIST_SNAPS")		\
	V(C_OSD_OP_SYNC_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0B, "C_OSD_OP_SYNC_READ")		\
	V(C_OSD_OP_TMAPGET,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0C, "C_OSD_OP_TMAPGET")		\
	V(C_OSD_OP_OMAPGETKEYS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x11, "C_OSD_OP_OMAPGETKEYS")	\
	V(C_OSD_OP_OMAPGETVALS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x12, "C_OSD_OP_OMAPGETVALS")	\
	V(C_OSD_OP_OMAPGETHEADER,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x13, "C_OSD_OP_OMAPGETHEADER")	\
	V(C_OSD_OP_OMAPGETVALSBYKEYS,  C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x14, "C_OSD_OP_OMAPGETVALSBYKEYS")	\
	V(C_OSD_OP_OMAP_CMP,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x19, "C_OSD_OP_OMAP_CMP")		\
	V(C_OSD_OP_COPY_GET_CLASSIC,   C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1B, "C_OSD_OP_COPY_GET_CLASSIC")	\
	V(C_OSD_OP_ISDIRTY,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1D, "C_OSD_OP_ISDIRTY")		\
	V(C_OSD_OP_COPY_GET,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1E, "C_OSD_OP_COPY_GET")		\
	V(C_OSD_OP_GETXATTR,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x01, "C_OSD_OP_GETXATTR")		\
	V(C_OSD_OP_GETXATTRS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x02, "C_OSD_OP_GETXATTRS")		\
	V(C_OSD_OP_CMPXATTR,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x03, "C_OSD_OP_CMPXATTR")		\
	V(C_OSD_OP_CALL,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_EXEC	 | 0x01, "C_OSD_OP_CALL")		\
	V(C_OSD_OP_PGLS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x01, "C_OSD_OP_PGLS")		\
	V(C_OSD_OP_PGLS_FILTER,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x02, "C_OSD_OP_PGLS_FILTER")	\
	V(C_OSD_OP_PG_HITSET_LS,       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x03, "C_OSD_OP_PG_HITSET_LS")	\
	V(C_OSD_OP_PG_HITSET_GET,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x04, "C_OSD_OP_PG_HITSET_GET")	\
	V(C_OSD_OP_ASSERT_SRC_VERSION, C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_MULTI | 0x02, "C_OSD_OP_ASSERT_SRC_VERSION") \
	V(C_OSD_OP_SRC_CMPXATTR,       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_MULTI | 0x03, "C_OSD_OP_SRC_CMPXATTR")	\
	V(C_OSD_OP_MODE_WR,	       0x2000,						 "C_OSD_OP_MODE_WR")		\
	V(C_OSD_OP_WRLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x01, "C_OSD_OP_WRLOCK")		\
	V(C_OSD_OP_WRUNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x02, "C_OSD_OP_WRUNLOCK")		\
	V(C_OSD_OP_RDLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x03, "C_OSD_OP_RDLOCK")		\
	V(C_OSD_OP_RDUNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x04, "C_OSD_OP_RDUNLOCK")		\
	V(C_OSD_OP_UPLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x05, "C_OSD_OP_UPLOCK")		\
	V(C_OSD_OP_DNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x06, "C_OSD_OP_DNLOCK")		\
	V(C_OSD_OP_WRITE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x01, "C_OSD_OP_WRITE")		\
	V(C_OSD_OP_WRITEFULL,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x02, "C_OSD_OP_WRITEFULL")		\
	V(C_OSD_OP_TRUNCATE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x03, "C_OSD_OP_TRUNCATE")		\
	V(C_OSD_OP_ZERO,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x04, "C_OSD_OP_ZERO")		\
	V(C_OSD_OP_DELETE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x05, "C_OSD_OP_DELETE")		\
	V(C_OSD_OP_APPEND,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x06, "C_OSD_OP_APPEND")		\
	V(C_OSD_OP_STARTSYNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x07, "C_OSD_OP_STARTSYNC")		\
	V(C_OSD_OP_SETTRUNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x08, "C_OSD_OP_SETTRUNC")		\
	V(C_OSD_OP_TRIMTRUNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x09, "C_OSD_OP_TRIMTRUNC")		\
	V(C_OSD_OP_TMAPPUT,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0B, "C_OSD_OP_TMAPPUT")		\
	V(C_OSD_OP_CREATE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0D, "C_OSD_OP_CREATE")		\
	V(C_OSD_OP_ROLLBACK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0E, "C_OSD_OP_ROLLBACK")		\
	V(C_OSD_OP_WATCH,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0F, "C_OSD_OP_WATCH")		\
	V(C_OSD_OP_OMAPSETVALS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x15, "C_OSD_OP_OMAPSETVALS")	\
	V(C_OSD_OP_OMAPSETHEADER,      C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x16, "C_OSD_OP_OMAPSETHEADER")	\
	V(C_OSD_OP_OMAPCLEAR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x17, "C_OSD_OP_OMAPCLEAR")		\
	V(C_OSD_OP_OMAPRMKEYS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x18, "C_OSD_OP_OMAPRMKEYS")		\
	V(C_OSD_OP_COPY_FROM,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x1A, "C_OSD_OP_COPY_FROM")		\
	V(C_OSD_OP_UNDIRTY,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x1C, "C_OSD_OP_UNDIRTY")		\
	V(C_OSD_OP_SETALLOCHINT,       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x23, "C_OSD_OP_SETALLOCHINT")	\
	V(C_OSD_OP_SETXATTR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x01, "C_OSD_OP_SETXATTR")		\
	V(C_OSD_OP_SETXATTRS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x02, "C_OSD_OP_SETXATTRS")		\
	V(C_OSD_OP_RESETXATTRS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x03, "C_OSD_OP_RESETXATTRS")	\
	V(C_OSD_OP_RMXATTR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x04, "C_OSD_OP_RMXATTR")		\
	V(C_OSD_OP_CLONERANGE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_MULTI | 0x01, "C_OSD_OP_CLONERANGE")		\
	V(C_OSD_OP_MODE_RMW,	       0x3000,						 "C_OSD_OP_MODE_RMW")		\
	V(C_OSD_OP_TMAPUP,	       C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA	 | 0x0A, "C_OSD_OP_TMAPUP")		\
	V(C_OSD_OP_TMAP2OMAP,	       C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA	 | 0x22, "C_OSD_OP_TMAP2OMAP")		\
	V(C_OSD_OP_MODE_SUB,	       0x4000,						 "C_OSD_OP_MODE_SUB")		\
	V(C_OSD_OP_PULL,	       C_OSD_OP_MODE_SUB			 | 0x01, "C_OSD_OP_PULL")		\
	V(C_OSD_OP_PUSH,	       C_OSD_OP_MODE_SUB			 | 0x02, "C_OSD_OP_PUSH")		\
	V(C_OSD_OP_BALANCEREADS,       C_OSD_OP_MODE_SUB			 | 0x03, "C_OSD_OP_BALANCEREADS")	\
	V(C_OSD_OP_UNBALANCEREADS,     C_OSD_OP_MODE_SUB			 | 0x04, "C_OSD_OP_UNBALANCEREADS")	\
	V(C_OSD_OP_SCRUB,	       C_OSD_OP_MODE_SUB			 | 0x05, "C_OSD_OP_SCRUB")		\
	V(C_OSD_OP_SCRUB_RESERVE,      C_OSD_OP_MODE_SUB			 | 0x06, "C_OSD_OP_SCRUB_RESERVE")	\
	V(C_OSD_OP_SCRUB_UNRESERVE,    C_OSD_OP_MODE_SUB			 | 0x07, "C_OSD_OP_SCRUB_UNRESERVE")	\
	V(C_OSD_OP_SCRUB_STOP,	       C_OSD_OP_MODE_SUB			 | 0x08, "C_OSD_OP_SCRUB_STOP")		\
	V(C_OSD_OP_SCRUB_MAP,	       C_OSD_OP_MODE_SUB			 | 0x09, "C_OSD_OP_SCRUB_MAP")		\
	V(C_OSD_OP_MODE_CACHE,	       0x8000,						 "C_OSD_OP_MODE_CACHE")		\
	V(C_OSD_OP_CACHE_FLUSH,	       C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x1F, "C_OSD_OP_CACHE_FLUSH")	\
	V(C_OSD_OP_CACHE_EVICT,	       C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x20, "C_OSD_OP_CACHE_EVICT")	\
	V(C_OSD_OP_CACHE_TRY_FLUSH,    C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x21, "C_OSD_OP_CACHE_TRY_FLUSH")	\
	V(C_OSD_OP_MODE,	       0xf000,						 "C_OSD_OP_MODE")

C_MAKE_STRINGS_EXT(c_osd_optype, 4)

#define c_poolop_type_strings_VALUE_STRING_LIST(V) \
	V(POOL_OP_CREATE,		 0x01, "Create")		    \
	V(POOL_OP_DELETE,		 0x02, "Delete")		    \
	V(POOL_OP_AUID_CHANGE,		 0x03, "Change Owner")		    \
	V(POOL_OP_CREATE_SNAP,		 0x11, "Create Snapshot")	    \
	V(POOL_OP_DELETE_SNAP,		 0x12, "Delete Snapshot")	    \
	V(POOL_OP_CREATE_UNMANAGED_SNAP, 0x21, "Create Unmanaged Snapshot") \
	V(POOL_OP_DELETE_UNMANAGED_SNAP, 0x22, "Delete Unmanaged Snapshot")

C_MAKE_STRINGS(c_poolop_type, 2)

#define c_mon_election_type_strings_VALUE_STRING_LIST(V) \
	V(C_MON_ELECTION_PROPOSE, 0x00000001, "Propose")	      \
	V(C_MON_ELECTION_ACK,	  0x00000002, "Acknowledge")	      \
	V(C_MON_ELECTION_NAK,	  0x00000003, "Negative Acknowledge") \
	V(C_MON_ELECTION_VICTORY, 0x00000004, "Victory")

C_MAKE_STRINGS_EXT(c_mon_election_type, 8)

#define c_mon_paxos_op_strings_VALUE_STRING_LIST(V) \
	V(C_MON_PAXOS_COLLECT,	0x00000001, "Propose Round")	    \
	V(C_MON_PAXOS_LAST,	0x00000002, "Accept Round")	    \
	V(C_MON_PAXOS_BEGIN,	0x00000003, "Propose Value")	    \
	V(C_MON_PAXOS_ACCEPT,	0x00000004, "Accept Value")	    \
	V(C_MON_PAXOS_COMMIT,	0x00000005, "Commit")		    \
	V(C_MON_PAXOS_LEASE,	0x00000006, "Extend Peon Lease")    \
	V(C_MON_PAXOS_LEASEACK, 0x00000007, "Lease Acknowledgment")

C_MAKE_STRINGS_EXT(c_mon_paxos_op, 8)

#define c_mon_probe_type_strings_VALUE_STRING_LIST(V) \
	V(C_MON_PROBE_PROBE,		0x00000001, "Probe")		\
	V(C_MON_PROBE_REPLY,		0x00000002, "Reply")		\
	V(C_MON_PROBE_SLURP,		0x00000003, "Slurp")		\
	V(C_MON_PROBE_SLURP_LATEST,	0x00000004, "Slurp Latest")	\
	V(C_MON_PROBE_DATA,		0x00000005, "Data")		\
	V(C_MON_PROBE_MISSING_FEATURES, 0x00000006, "Missing Features")

C_MAKE_STRINGS_EXT(c_mon_probe_type, 8)

#define c_osd_ping_op_strings_VALUE_STRING_LIST(V) \
	V(C_TIMECHECK_HEARTBEAT,       0x00, "Heartbeat")	 \
	V(C_TIMECHECK_START_HEARTBEAT, 0x01, "Start Heartbeats") \
	V(C_TIMECHECK_YOU_DIED,	       0x02, "You Died")	 \
	V(C_TIMECHECK_STOP_HEARTBEAT,  0x03, "Stop Heartbeats")	 \
	V(C_TIMECHECK_PING,	       0x04, "Ping")		 \
	V(C_TIMECHECK_PING_REPLY,      0x05, "Pong")

C_MAKE_STRINGS_EXT(c_osd_ping_op, 2)

#define c_session_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_SESSION_REQUEST_OPEN,      0x00000000, "Request Open")	 \
	V(C_SESSION_OPEN,	       0x00000001, "Open")		 \
	V(C_SESSION_REQUEST_CLOSE,     0x00000002, "Request Close")	 \
	V(C_SESSION_CLOSE,	       0x00000003, "Close")		 \
	V(C_SESSION_REQUEST_RENEWCAPS, 0x00000004, "Request Renew Caps") \
	V(C_SESSION_RENEWCAPS,	       0x00000005, "Renew Caps")	 \
	V(C_SESSION_STALE,	       0x00000006, "Stale")		 \
	V(C_SESSION_RECALL_STATE,      0x00000007, "Recall Stale")	 \
	V(C_SESSION_FLUSHMSG,	       0x00000008, "Flush Message")	 \
	V(C_SESSION_FLUSHMSG_ACK,      0x00000009, "Flush Message Ack")

C_MAKE_STRINGS_EXT(c_session_op_type, 8)

#define c_mds_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_MDS_OP_LOOKUP,	 0x00000100, "MDS_OP_LOOKUP")	    \
	V(C_MDS_OP_GETATTR,	 0x00000101, "MDS_OP_GETATTR")	    \
	V(C_MDS_OP_LOOKUPHASH,	 0x00000102, "MDS_OP_LOOKUPHASH")   \
	V(C_MDS_OP_LOOKUPPARENT, 0x00000103, "MDS_OP_LOOKUPPARENT") \
	V(C_MDS_OP_LOOKUPINO,	 0x00000104, "MDS_OP_LOOKUPINO")    \
	V(C_MDS_OP_LOOKUPNAME,	 0x00000105, "MDS_OP_LOOKUPNAME")   \
	V(C_MDS_OP_GETFILELOCK,	 0x00000110, "MDS_OP_GETFILELOCK")  \
	V(C_MDS_OP_OPEN,	 0x00000302, "MDS_OP_OPEN")	    \
	V(C_MDS_OP_READDIR,	 0x00000305, "MDS_OP_READDIR")	    \
	V(C_MDS_OP_LOOKUPSNAP,	 0x00000400, "MDS_OP_LOOKUPSNAP")   \
	V(C_MDS_OP_LSSNAP,	 0x00000402, "MDS_OP_LSSNAP")	    \
	V(C_MDS_OP_WRITE,	 0x00001000, "MDS_OP_WRITE")	    \
	V(C_MDS_OP_SETXATTR,	 0x00001105, "MDS_OP_SETXATTR")	    \
	V(C_MDS_OP_RMXATTR,	 0x00001106, "MDS_OP_RMXATTR")	    \
	V(C_MDS_OP_SETLAYOUT,	 0x00001107, "MDS_OP_SETLAYOUT")    \
	V(C_MDS_OP_SETATTR,	 0x00001108, "MDS_OP_SETATTR")	    \
	V(C_MDS_OP_SETFILELOCK,	 0x00001109, "MDS_OP_SETFILELOCK")  \
	V(C_MDS_OP_SETDIRLAYOUT, 0x0000110a, "MDS_OP_SETDIRLAYOUT") \
	V(C_MDS_OP_MKNOD,	 0x00001201, "MDS_OP_MKNOD")	    \
	V(C_MDS_OP_LINK,	 0x00001202, "MDS_OP_LINK")	    \
	V(C_MDS_OP_UNLINK,	 0x00001203, "MDS_OP_UNLINK")	    \
	V(C_MDS_OP_RENAME,	 0x00001204, "MDS_OP_RENAME")	    \
	V(C_MDS_OP_MKDIR,	 0x00001220, "MDS_OP_MKDIR")	    \
	V(C_MDS_OP_RMDIR,	 0x00001221, "MDS_OP_RMDIR")	    \
	V(C_MDS_OP_SYMLINK,	 0x00001222, "MDS_OP_SYMLINK")	    \
	V(C_MDS_OP_CREATE,	 0x00001301, "MDS_OP_CREATE")	    \
	V(C_MDS_OP_MKSNAP,	 0x00001400, "MDS_OP_MKSNAP")	    \
	V(C_MDS_OP_RMSNAP,	 0x00001401, "MDS_OP_RMSNAP")	    \
	V(C_MDS_OP_FRAGMENTDIR,	 0x00001500, "MDS_OP_FRAGMENTDIR")  \
	V(C_MDS_OP_EXPORTDIR,	 0x00001501, "MDS_OP_EXPORTDIR")

C_MAKE_STRINGS_EXT(c_mds_op_type, 8)

#define c_cap_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_CAP_OP_GRANT,	  0x00000000, "mds->client grant")		      \
	V(C_CAP_OP_REVOKE,	  0x00000001, "mds->client revoke")		      \
	V(C_CAP_OP_TRUNC,	  0x00000002, "mds->client trunc notify")	      \
	V(C_CAP_OP_EXPORT,	  0x00000003, "mds has exported the cap")	      \
	V(C_CAP_OP_IMPORT,	  0x00000004, "mds has imported the cap")	      \
	V(C_CAP_OP_UPDATE,	  0x00000005, "client->mds update")		      \
	V(C_CAP_OP_DROP,	  0x00000006, "client->mds drop cap bits")	      \
	V(C_CAP_OP_FLUSH,	  0x00000007, "client->mds cap writeback")	      \
	V(C_CAP_OP_FLUSH_ACK,	  0x00000008, "mds->client flushed")		      \
	V(C_CAP_OP_FLUSHSNAP,	  0x00000009, "client->mds flush snapped metadata")   \
	V(C_CAP_OP_FLUSHSNAP_ACK, 0x0000000A, "mds->client flushed snapped metadata") \
	V(C_CAP_OP_RELEASE,	  0x0000000B, "client->mds release (clean) cap")      \
	V(C_CAP_OP_RENEW,	  0x0000000C, "client->mds renewal request")

C_MAKE_STRINGS_EXT(c_cap_op_type, 8)

#define c_timecheck_op_strings_VALUE_STRING_LIST(V) \
	V(C_TIMECHECK_OP_PING,	 0x00000001, "Ping")   \
	V(C_TIMECHECK_OP_PONG,	 0x00000002, "Pong")   \
	V(C_TIMECHECK_OP_REPORT, 0x00000003, "Report")

C_MAKE_STRINGS_EXT(c_timecheck_op, 8)

#define c_pgpool_type_strings_VALUE_STRING_LIST(V) \
	V(C_PGPOOL_REPLICATED, 0x01, "Replicated")    \
	V(C_PGPOOL_RAID4,      0x02, "Raid4")	      \
	V(C_PGPOOL_ERASURE,    0x03, "Erasure-coded")

C_MAKE_STRINGS(c_pgpool_type, 2)

#define c_pgpool_cachemode_strings_VALUE_STRING_LIST(V) \
	V(C_PGPOOL_CACHEMODE_NONE,	0x00, "No caching")						\
	V(C_PGPOOL_CACHEMODE_WRITEBACK, 0x01, "Write to cache, flush later")				\
	V(C_PGPOOL_CACHEMODE_FORWARD,	0x02, "Forward if not in cache")				\
	V(C_PGPOOL_CACHEMODE_READONLY,	0x03, "Handle reads, forward writes [not strongly consistent]")

C_MAKE_STRINGS_EXT(c_pgpool_cachemode, 2)

#define c_pgpool_pg_autoscalemode_strings_VALUE_STRING_LIST(V) \
	V(C_PGPOOL_PG_AUTOSCALEMODE_OFF,	0x00, "OFF")	\
	V(C_PGPOOL_PG_AUTOSCALEMODE_WARN,	0x01, "WARN")	\
	V(C_PGPOOL_PG_AUTOSCALEMODE_ON,		0x02, "ON")

C_MAKE_STRINGS_EXT(c_pgpool_pg_autoscalemode, 2)

#define c_hitset_params_type_strings_VALUE_STRING_LIST(V) \
	V(C_HITSET_PARAMS_TYPE_NONE,		0x00, "None")		 \
	V(C_HITSET_PARAMS_TYPE_EXPLICIT_HASH,	0x01, "Explicit Hash")	 \
	V(C_HITSET_PARAMS_TYPE_EXPLICIT_OBJECT, 0x02, "Explicit Object") \
	V(C_HITSET_PARAMS_TYPE_BLOOM,		0x03, "Bloom Filter")

C_MAKE_STRINGS_EXT(c_hitset_params_type, 2)

#define c_auth_proto_strings_VALUE_STRING_LIST(V) \
	V(C_AUTH_PROTO_UNKNOWN, 0x00, "Undecided") \
	V(C_AUTH_PROTO_NONE,	0x01, "None")	   \
	V(C_AUTH_PROTO_CEPHX,	0x02, "CephX")

C_MAKE_STRINGS(c_auth_proto, 2)

#define c_cephx_req_type_strings_VALUE_STRING_LIST(V) \
	V(C_CEPHX_REQ_AUTH_SESSIONKEY, 0x0100, "Get Auth Session Key")		 \
	V(C_CEPHX_REQ_PRINCIPAL_SESSIONKEY, 0x0200, "Get Principal Session Key") \
	V(C_CEPHX_REQ_ROTATINGKEY, 0x0400, "Get Rotating Key")

C_MAKE_STRINGS(c_cephx_req_type, 4)

/** Entityaddr type database. */
#define c_entityaddr_type_strings_LIST(V, W) \
	V(C_ENTITYADDR_TYPE_NONE,   0, W("NONE",	"none")) \
	V(C_ENTITYADDR_TYPE_LEGACY, 1, W("LEGACY",	"legacy")) \
	V(C_ENTITYADDR_TYPE_MSGR2,  2, W("MSGR2",	"msgr2")) \
	V(C_ENTITYADDR_TYPE_ANY,    3, W("ANY",		"any"))

/** Node type database. */
#define c_node_type_strings_LIST(V, W) \
	V(C_NODE_TYPE_UNKNOWN, 0x00, W("Unknown",		"unknown")) \
	V(C_NODE_TYPE_MON,     0x01, W("Monitor",		"mon"	 )) \
	V(C_NODE_TYPE_MDS,     0x02, W("Meta Data Server",	"mds"	 )) \
	V(C_NODE_TYPE_OSD,     0x04, W("Object Storage Daemon", "osd"	 )) \
	V(C_NODE_TYPE_CLIENT,  0x08, W("Client",		"client" )) \
	V(C_NODE_TYPE_AUTH,    0x20, W("Authentication Server", "auth"	 ))

#define C_EXTRACT_1(a, b) a
#define C_EXTRACT_2(a, b) b

/** Extract the full names to create a value_string list. */
#define c_entityaddr_type_strings_VALUE_STRING_LIST(V) \
	c_entityaddr_type_strings_LIST(V, C_EXTRACT_1)

#define c_node_type_strings_VALUE_STRING_LIST(V) \
	c_node_type_strings_LIST(V, C_EXTRACT_1)

C_MAKE_STRINGS(c_entityaddr_type, 2)
C_MAKE_STRINGS(c_node_type, 2)

/** Extract the abbreviations to create a value_string list. */
#define c_entityaddr_type_abbr_strings_VALUE_STRING_LIST(V) \
	c_entityaddr_type_strings_LIST(V, C_EXTRACT_2)

#define c_node_type_abbr_strings_VALUE_STRING_LIST(V) \
	c_node_type_strings_LIST(V, C_EXTRACT_2)

VALUE_STRING_ARRAY(c_node_type_abbr_strings);

static
const char *c_node_type_abbr_string(c_node_type val)
{
	return val_to_str(val, c_node_type_abbr_strings, "Unknown (0x%02x)");
}

/** PGLog OP. */
#define c_pglog_op_strings_VALUE_STRING_LIST(V) \
	V(C_PGLOG_OP_MODIFY,	  1,  "modify") \
	V(C_PGLOG_OP_CLONE,	  2,  "clone") \
	V(C_PGLOG_OP_DELETE,	  3,  "delete") \
	V(C_PGLOG_OP_BACKLOG,	  4,  "backlog") \
	V(C_PGLOG_OP_LOST_REVERT, 5,  "l_revert") \
	V(C_PGLOG_OP_LOST_DELETE, 6,  "l_delete") \
	V(C_PGLOG_OP_LOST_MARK,	  7,  "l_mark") \
	V(C_PGLOG_OP_PROMOTE,	  8,  "promote") \
	V(C_PGLOG_OP_CLEAN,	  9,  "clean") \
	V(C_PGLOG_OP_ERROR,	  10, "error")

C_MAKE_STRINGS_EXT(c_pglog_op, 2)

/** Moddesc Op Code. */
#define c_moddesc_op_code_strings_VALUE_STRING_LIST(V) \
	V(C_MODDESC_OP_CODE_APPEND,		1, "APPEND") \
	V(C_MODDESC_OP_CODE_SETATTRS,		2, "SETATTRS") \
	V(C_MODDESC_OP_CODE_DELETE,		3, "DELETE") \
	V(C_MODDESC_OP_CODE_CREATE,		4, "CREATE") \
	V(C_MODDESC_OP_CODE_UPDATE_SNAPS,	5, "UPDATE_SNAPS") \
	V(C_MODDESC_OP_CODE_TRY_DELETE,		6, "TRY_DELETE") \
	V(C_MODDESC_OP_CODE_ROLLBACK_EXTENTS,	7, "ROLLBACK_EXTENTS")

C_MAKE_STRINGS_EXT(c_moddesc_op_code, 2)

/** PG Missing Flags. */
#define c_pg_missing_flags_strings_VALUE_STRING_LIST(V) \
	V(C_PG_MISSING_FLAGS_NONE,	0, "NONE") \
	V(C_PG_MISSING_FLAGS_DELETE,	1, "DELETE")

C_MAKE_STRINGS_EXT(c_pg_missing_flags, 1)

#define C_MON_SUB_FLAG_ONETIME  0x01

typedef enum _c_state {
	C_STATE_INIT = 0,
	C_STATE_HANDSHAKE,
	C_STATE_OPEN,
	C_STATE_SEQ /* Waiting for sequence number. */
} c_state;

typedef enum _c_state2 {
	C_STATE2_INIT = 50,
	C_STATE2_HANDSHAKE,
	C_STATE2_MSG
} c_state2;

typedef struct _c_node_name {
	const char *slug;
	const char *type_str;
	guint64 id;
	c_node_type type;
} c_entityname;

static
void c_node_name_init(c_entityname *d)
{
	d->slug	    = NULL;
	d->type_str = NULL;
	d->id	    = G_MAXUINT64;
	d->type	    = C_NODE_TYPE_UNKNOWN;
}

typedef struct _c_node {
	address addr;
	c_entityname name;
	c_state state; /* ceph msgr1 state */
	c_state2 state2; /* ceph msgr2 state */
	guint16 port;
} c_node;

static
void c_node_init(c_node *n)
{
	clear_address(&n->addr);
	c_node_name_init(&n->name);
	n->port = 0xFFFF;
	n->state = C_STATE_INIT;
	n->state2 = C_STATE2_INIT;
}

static
c_node *c_node_copy(c_node *src, c_node *dst)
{
	dst->name = src->name;
	copy_address_shallow(&dst->addr, &src->addr);
	dst->port = src->port;
	dst->state = src->state;
	dst->state2 = src->state2;

	return dst;
}

typedef struct _c_eversion {
	guint64 ver;
	guint32 epoch;
} c_eversion;

typedef struct _c_conv_data {
	c_node client; /* The node that initiated this connection. */
	c_node server; /* The other node. */
	gboolean new_conversation; /* Whether the ceph conversation is new */
} c_conv_data;

static
void c_conv_data_init(c_conv_data *d)
{
	c_node_init(&d->client);
	c_node_init(&d->server);
}

static
c_conv_data *c_conv_data_copy(c_conv_data *src, c_conv_data *dst)
{
	c_node_copy(&src->client, &dst->client);
	c_node_copy(&src->server, &dst->server);

	return dst;
}

static
c_conv_data *c_conv_data_clone(c_conv_data *d)
{
	return c_conv_data_copy(d, wmem_new(wmem_file_scope(), c_conv_data));
}

static
c_conv_data *c_conv_data_new(void)
{
	c_conv_data *r;
	r = wmem_new(wmem_file_scope(), c_conv_data);
	c_conv_data_init(r);
	return r;
}

typedef struct _c_header {
	guint64 seq;
	guint64 tid;
	c_msg_type type;
	guint16 ver;
	guint16 priority;
	c_entityname src;
} c_header;

static
void c_header_init(c_header *h)
{
	h->seq	    = 0;
	h->tid	    = 0;
	h->type	    = C_MSG_UNKNOWN;
	h->priority = 0;
	h->ver	    = 0;
	memset(&h->src, 0, sizeof(h->src));
}

typedef struct _c_pkt_data {
	conversation_t *conv;	/* The wireshark conversation. */
	c_conv_data *convd;	/* The Ceph conversation data. */
	c_node *src;		/* The node in convd that sent this message. */
	c_node *dst;		/* The node in convd that is receiving this message. */

	proto_item  *item_root;	/* The root proto_item for the message. */
	packet_info *pinfo;

	c_header header;	/* The MSG header. */
} c_pkt_data;

#define C_SIZE_SOCKADDR_STORAGE 128

typedef struct _c_sockaddr {
	const gchar *str;      /** A string representing the entire address. */
	const gchar *addr_str; /** A string representing the address portion. */

	c_inet af;	       /** Address family. */
	guint16 port;	       /** Network Port. */
} c_sockaddr;

#define C_SIZE_LEGACY_ENTITY_ADDR (4 + 4 + C_SIZE_SOCKADDR_STORAGE)
#define C_SIZE_ENTITY_TYPE 1
#define C_SIZE_ENTITY_ADDR 35

typedef struct _c_entity_addr {
	c_sockaddr addr;
	const char *type_str;
	c_entityaddr_type type;
} c_entityaddr;

static guint32 ceph_ms_bind_port_min	= 6800;
static guint32 ceph_ms_bind_port_max	= 7300;

extern void c_pkt_data_init(c_pkt_data *, packet_info *, int, guint);
extern void c_pkt_data_save(c_pkt_data *, packet_info *, int, guint);
extern gboolean c_from_client(c_pkt_data *);
extern gboolean c_from_server(c_pkt_data *);
extern void c_set_type(c_pkt_data *, const char *);

extern guint c_dissect_entityaddr(proto_tree *, int, c_entityaddr *, tvbuff_t *, guint, c_pkt_data *);
extern guint c_dissect_msg(proto_tree *, tvbuff_t *, guint, c_pkt_data *);

#endif
