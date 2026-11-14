/* packet-dash.c
 * Routines for Dash P2P network protocol dissection
 *
 * Copyright 2026, thephez
 *
 * Dash is a cryptocurrency derived from Bitcoin.  Its P2P protocol shares
 * the Bitcoin message framing and many Bitcoin messages, and adds messages
 * for masternodes, long-living masternode quorums (LLMQs), ChainLocks,
 * InstantSend, CoinJoin, governance, sporks, compressed headers and
 * special (DIP-0002) transactions.
 *
 * References:
 *   https://github.com/dashpay/dash (Dash Core, protocol version 70242)
 *   https://github.com/dashpay/dips
 *   https://docs.dash.org/projects/core/en/latest/docs/reference/p2p-network.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <wsutil/array.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/pint.h>
#include <wsutil/to_str.h>

#include "packet-tcp.h"

void proto_register_dash(void);
void proto_reg_handoff_dash(void);

/*
 * Message header:
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 * - Checksum - 4 bytes
 */
#define DASH_HEADER_LENGTH (4+12+4+4)

/* Network magic, as read big-endian from the wire (pchMessageStart) */
#define DASH_MAGIC_MAINNET  0xBF0C6BBD
#define DASH_MAGIC_TESTNET  0xCEE2CAFF
#define DASH_MAGIC_DEVNET   0xE2CAFFCE
#define DASH_MAGIC_REGTEST  0xFCC1B7DC

/*
 * Default P2P ports are 9999 (mainnet), 19999 (testnet), 19799 (devnet) and
 * 19899 (regtest).  They are not registered by default: 9999 is used by the
 * TP-Link Smart Home dissector and 19999 is the IANA port for DNP3 over TLS.
 * Dash connections are found by the heuristic dissector (network magic plus
 * a valid command name); set the "tcp.port" preference for Dash, or enable
 * TCP's "Try heuristic sub-dissectors first", when another dissector claims
 * the port (e.g. testnet traffic on 19999).
 */
#define DASH_PORT_RANGE     ""

/* Protocol versions (src/version.h) */
#define DASH_PROTOCOL_VERSION                       70242
#define DASH_ADDRV2_PROTO_VERSION                   70223
#define DASH_BLS_SCHEME_PROTO_VERSION               70225
#define DASH_DMN_TYPE_PROTO_VERSION                 70227
#define DASH_SMNLE_VERSIONED_PROTO_VERSION          70228
#define DASH_MNLISTDIFF_VERSION_ORDER               70229
#define DASH_MNLISTDIFF_CHAINLOCKS_PROTO_VERSION    70230
#define DASH_NO_LEGACY_ISLOCK_PROTO_VERSION         70231
#define DASH_DSQ_INV_VERSION                        70234
#define DASH_EFFICIENT_QRINFO_VERSION               70236
#define DASH_ISDLOCK_CYCLEHASH_UPDATE_VERSION       70237
#define DASH_PLATFORM_BAN_VERSION                   70238

#define DASH_HASH_LEN       32
#define DASH_BLS_PUBKEY_LEN 48
#define DASH_BLS_SIG_LEN    96
#define DASH_BLS_SKEY_LEN   32
#define DASH_HEADER_SIZE    80

static const value_string dash_magic_vals[] = {
  { DASH_MAGIC_MAINNET, "Mainnet" },
  { DASH_MAGIC_TESTNET, "Testnet" },
  { DASH_MAGIC_DEVNET,  "Devnet" },
  { DASH_MAGIC_REGTEST, "Regtest" },
  { 0, NULL }
};

static const value_string dash_inv_types[] = {
  {  0, "UNDEFINED" },
  {  1, "MSG_TX" },
  {  2, "MSG_BLOCK" },
  {  3, "MSG_FILTERED_BLOCK" },
  {  4, "MSG_LEGACY_TXLOCK_REQUEST (retired)" },
  {  5, "MSG_TXLOCK_VOTE (retired)" },
  {  6, "MSG_SPORK" },
  {  7, "MSG_MASTERNODE_PAYMENT_VOTE (retired)" },
  {  8, "MSG_MASTERNODE_PAYMENT_BLOCK (retired)" },
  {  9, "MSG_BUDGET_VOTE (retired)" },
  { 10, "MSG_BUDGET_PROPOSAL (retired)" },
  { 11, "MSG_BUDGET_FINALIZED (retired)" },
  { 12, "MSG_BUDGET_FINALIZED_VOTE (retired)" },
  { 13, "MSG_MASTERNODE_QUORUM (retired)" },
  { 14, "MSG_MASTERNODE_ANNOUNCE (retired)" },
  { 15, "MSG_MASTERNODE_PING (retired)" },
  { 16, "MSG_DSTX" },
  { 17, "MSG_GOVERNANCE_OBJECT" },
  { 18, "MSG_GOVERNANCE_OBJECT_VOTE" },
  { 19, "MSG_MASTERNODE_VERIFY (retired)" },
  { 20, "MSG_CMPCT_BLOCK" },
  { 21, "MSG_QUORUM_FINAL_COMMITMENT" },
  { 22, "MSG_QUORUM_DUMMY_COMMITMENT (retired)" },
  { 23, "MSG_QUORUM_CONTRIB" },
  { 24, "MSG_QUORUM_COMPLAINT" },
  { 25, "MSG_QUORUM_JUSTIFICATION" },
  { 26, "MSG_QUORUM_PREMATURE_COMMITMENT" },
  { 27, "MSG_QUORUM_DEBUG_STATUS (retired)" },
  { 28, "MSG_QUORUM_RECOVERED_SIG" },
  { 29, "MSG_CLSIG" },
  { 30, "MSG_ISLOCK (retired)" },
  { 31, "MSG_ISDLOCK" },
  { 32, "MSG_DSQ" },
  { 33, "MSG_PLATFORM_BAN" },
  { 34, "MSG_ASSET_UNLOCK" },
  { 0, NULL }
};
static value_string_ext dash_inv_types_ext = VALUE_STRING_EXT_INIT(dash_inv_types);

/* BIP155 network IDs */
static const value_string dash_network_ids[] = {
  { 1, "IPv4" },
  { 2, "IPv6" },
  { 3, "Tor v2" },
  { 4, "Tor v3" },
  { 5, "I2P" },
  { 6, "Cjdns" },
  { 0, NULL }
};

static const value_string dash_tx_types[] = {
  {  0, "Normal" },
  {  1, "Provider Register (ProRegTx)" },
  {  2, "Provider Update Service (ProUpServTx)" },
  {  3, "Provider Update Registrar (ProUpRegTx)" },
  {  4, "Provider Update Revoke (ProUpRevTx)" },
  {  5, "Coinbase (CbTx)" },
  {  6, "Quorum Commitment (QcTx)" },
  {  7, "Masternode Hard Fork Signal (MnHfTx)" },
  {  8, "Asset Lock" },
  {  9, "Asset Unlock" },
  { 10, "Provider Dissolve (ProDisTx)" },
  { 11, "Provider Update Share (ProUpShareTx)" },
  { 12, "Provider Update Shared Registrar (ProUpSharedRegTx)" },
  { 0, NULL }
};

static const value_string dash_protx_versions[] = {
  { 1, "Legacy BLS" },
  { 2, "Basic BLS" },
  { 3, "Extended addresses" },
  { 0, NULL }
};

static const value_string dash_mn_types[] = {
  { 0,      "Regular" },
  { 1,      "Evo" },
  { 0xffff, "Invalid" },
  { 0, NULL }
};

static const value_string dash_revoke_reasons[] = {
  { 0, "Not specified" },
  { 1, "Termination of service" },
  { 2, "Compromised keys" },
  { 3, "Change of keys" },
  { 0, NULL }
};

static const value_string dash_netinfo_purposes[] = {
  { 0, "Core P2P" },
  { 1, "Platform P2P" },
  { 2, "Platform HTTPS" },
  { 0, NULL }
};

static const value_string dash_netinfo_entry_types[] = {
  { 0x01, "Service" },
  { 0x02, "Domain" },
  { 0xff, "Invalid" },
  { 0, NULL }
};

static const value_string dash_cbtx_versions[] = {
  { 0, "Invalid" },
  { 1, "Merkle root of masternode list" },
  { 2, "Merkle root of quorums" },
  { 3, "Best ChainLock and credit pool balance" },
  { 4, "Merkle root of asset unlocks" },
  { 0, NULL }
};

static const value_string dash_qc_versions[] = {
  { 1, "Legacy BLS, non-indexed" },
  { 2, "Legacy BLS, indexed (rotation)" },
  { 3, "Basic BLS, non-indexed" },
  { 4, "Basic BLS, indexed (rotation)" },
  { 0, NULL }
};

static const value_string dash_llmq_types[] = {
  {   1, "LLMQ_50_60" },
  {   2, "LLMQ_400_60" },
  {   3, "LLMQ_400_85" },
  {   4, "LLMQ_100_67" },
  {   5, "LLMQ_60_75" },
  {   6, "LLMQ_25_67" },
  { 100, "LLMQ_TEST" },
  { 101, "LLMQ_DEVNET" },
  { 102, "LLMQ_TEST_V17" },
  { 103, "LLMQ_TEST_DIP0024" },
  { 104, "LLMQ_TEST_INSTANTSEND" },
  { 105, "LLMQ_DEVNET_DIP0024" },
  { 106, "LLMQ_TEST_PLATFORM" },
  { 107, "LLMQ_DEVNET_PLATFORM" },
  { 255, "LLMQ_NONE" },
  { 0, NULL }
};

static const value_string dash_asset_versions[] = {
  { 1, "Initial" },
  { 2, "Current" },
  { 0, NULL }
};

static const value_string dash_filter_types[] = {
  { 0, "Basic" },
  { 0, NULL }
};

static const value_string dash_script_types[] = {
  { 0, "Non-standard" },
  { 1, "Pay to public key hash (P2PKH)" },
  { 2, "Pay to script hash (P2SH)" },
  { 3, "Pay to public key (P2PK)" },
  { 4, "Null data (OP_RETURN)" },
  { 5, "Multisig" },
  { 6, "Empty" },
  { 0, NULL }
};

static const value_string dash_hdr2_version_offsets[] = {
  { 0, "Version present" },
  { 1, "Most recent version #1" },
  { 2, "Most recent version #2" },
  { 3, "Most recent version #3" },
  { 4, "Most recent version #4" },
  { 5, "Most recent version #5" },
  { 6, "Most recent version #6" },
  { 7, "Most recent version #7" },
  { 0, NULL }
};

static const true_false_string tfs_dash_present_compressed = { "Present", "Compressed" };

static const value_string dash_bloom_flags[] = {
  { 0, "BLOOM_UPDATE_NONE" },
  { 1, "BLOOM_UPDATE_ALL" },
  { 2, "BLOOM_UPDATE_P2PUBKEY_ONLY" },
  { 0, NULL }
};

static int proto_dash;

static dissector_handle_t dash_handle;
static dissector_table_t  dash_command_table;

static int hf_dash_magic;
static int hf_dash_command;
static int hf_dash_length;
static int hf_dash_checksum;
static int hf_dash_checksum_status;
static int hf_dash_payload;
static int hf_dash_payload_data;
static int hf_dash_varbytes_length;
static int hf_dash_address;
static int hf_dash_script_type;
static int hf_dash_outpoint_hash;
static int hf_dash_outpoint_index;
static int hf_dash_bitset_size;
static int hf_dash_bitset_count;
static int hf_dash_bitset_members;
static int hf_dash_service_ipv6;
static int hf_dash_service_ipv4;
static int hf_dash_service_port;
static int hf_dash_service_network;
static int hf_dash_service_addr_len;
static int hf_dash_service_addr_other;
static int hf_dash_netinfo_service;
static int hf_dash_netinfo;
static int hf_dash_netinfo_version;
static int hf_dash_netinfo_purpose_count;
static int hf_dash_netinfo_purpose_entry;
static int hf_dash_netinfo_purpose;
static int hf_dash_netinfo_entry_count;
static int hf_dash_netinfo_entry;
static int hf_dash_netinfo_entry_type;
static int hf_dash_netinfo_domain;
static int hf_dash_netinfo_domain_port;
static int hf_dash_tx;
static int hf_dash_tx_version;
static int hf_dash_tx_type;
static int hf_dash_tx_in_count;
static int hf_dash_tx_in;
static int hf_dash_tx_in_prevout;
static int hf_dash_tx_in_script;
static int hf_dash_tx_in_sequence;
static int hf_dash_tx_out_count;
static int hf_dash_tx_out;
static int hf_dash_tx_out_value;
static int hf_dash_tx_out_script;
static int hf_dash_tx_lock_time;
static int hf_dash_tx_payload;
static int hf_dash_tx_payload_size;
static int hf_dash_tx_payload_data;
static int hf_dash_tx_txid;
static int hf_dash_tx_instance_hash;
static int hf_dash_block_header;
static int hf_dash_block_version;
static int hf_dash_block_prev;
static int hf_dash_block_merkle_root;
static int hf_dash_block_time;
static int hf_dash_block_bits;
static int hf_dash_block_nonce;
static int hf_dash_block_tx_count;
static int hf_dash_commitment;
static int hf_dash_qc_version;
static int hf_dash_llmq_type;
static int hf_dash_quorum_hash;
static int hf_dash_quorum_index;
static int hf_dash_qc_signers;
static int hf_dash_qc_valid_members;
static int hf_dash_qc_quorum_pubkey;
static int hf_dash_qc_vvec_hash;
static int hf_dash_qc_quorum_sig;
static int hf_dash_qc_members_sig;
static int hf_dash_protx_version;
static int hf_dash_protx_mn_type;
static int hf_dash_protx_mode;
static int hf_dash_protx_collateral;
static int hf_dash_protx_hash;
static int hf_dash_protx_owner_keyid;
static int hf_dash_protx_operator_pubkey;
static int hf_dash_protx_voting_keyid;
static int hf_dash_protx_operator_reward;
static int hf_dash_protx_payout_script;
static int hf_dash_protx_operator_payout_script;
static int hf_dash_protx_payout_count;
static int hf_dash_protx_payout;
static int hf_dash_protx_payout_reward;
static int hf_dash_protx_share_count;
static int hf_dash_protx_share;
static int hf_dash_protx_share_amount;
static int hf_dash_protx_share_refund_script;
static int hf_dash_protx_share_reward_script;
static int hf_dash_protx_share_index;
static int hf_dash_protx_join_sig;
static int hf_dash_protx_early_period;
static int hf_dash_protx_early_penalty;
static int hf_dash_protx_inputs_hash;
static int hf_dash_protx_platform_node_id;
static int hf_dash_protx_platform_p2p_port;
static int hf_dash_protx_platform_http_port;
static int hf_dash_protx_sig;
static int hf_dash_protx_bls_sig;
static int hf_dash_protx_revoke_reason;
static int hf_dash_protx_actor_index;
static int hf_dash_protx_sig_count;
static int hf_dash_protx_compact_sig;
static int hf_dash_cbtx_version;
static int hf_dash_cbtx_height;
static int hf_dash_cbtx_merkle_mnlist;
static int hf_dash_cbtx_merkle_quorums;
static int hf_dash_cbtx_best_cl_height_diff;
static int hf_dash_cbtx_best_cl_sig;
static int hf_dash_cbtx_credit_pool;
static int hf_dash_cbtx_merkle_asset_unlocks;
static int hf_dash_qctx_version;
static int hf_dash_qctx_height;
static int hf_dash_mnhf_version;
static int hf_dash_mnhf_version_bit;
static int hf_dash_mnhf_sig;
static int hf_dash_asset_version;
static int hf_dash_assetlock_output_count;
static int hf_dash_assetlock_output;
static int hf_dash_assetunlock_index;
static int hf_dash_assetunlock_fee;
static int hf_dash_assetunlock_requested_height;
static int hf_dash_assetunlock_quorum_sig;
static int hf_dash_services;
static int hf_dash_services_network;
static int hf_dash_services_bloom;
static int hf_dash_services_compact_filters;
static int hf_dash_services_network_limited;
static int hf_dash_services_headers_compressed;
static int hf_dash_services_p2p_v2;
static int hf_dash_version_version;
static int hf_dash_version_timestamp;
static int hf_dash_version_addr_recv;
static int hf_dash_version_addr_from;
static int hf_dash_version_nonce;
static int hf_dash_version_user_agent;
static int hf_dash_version_start_height;
static int hf_dash_version_relay;
static int hf_dash_version_mnauth_challenge;
static int hf_dash_version_masternode;
static int hf_dash_addr_count;
static int hf_dash_addr_entry;
static int hf_dash_addr_timestamp;
static int hf_dash_inv_count;
static int hf_dash_inv_entry;
static int hf_dash_inv_type;
static int hf_dash_inv_hash;
static int hf_dash_locator_version;
static int hf_dash_locator_count;
static int hf_dash_locator_hash;
static int hf_dash_locator_stop;
static int hf_dash_headers_count;
static int hf_dash_headers_entry;
static int hf_dash_headers_tx_count;
static int hf_dash_hdr2_flags;
static int hf_dash_hdr2_flag_version;
static int hf_dash_hdr2_flag_prev;
static int hf_dash_hdr2_flag_time;
static int hf_dash_hdr2_flag_bits;
static int hf_dash_hdr2_time_offset;
static int hf_dash_ping_nonce;
static int hf_dash_filter_data;
static int hf_dash_filter_hash_funcs;
static int hf_dash_filter_tweak;
static int hf_dash_filter_flags;
static int hf_dash_merkle_total_tx;
static int hf_dash_merkle_hash_count;
static int hf_dash_merkle_hash;
static int hf_dash_merkle_flags;
static int hf_dash_cmpct_announce;
static int hf_dash_cmpct_version;
static int hf_dash_cmpct_nonce;
static int hf_dash_cmpct_shortid_count;
static int hf_dash_cmpct_shortid;
static int hf_dash_cmpct_prefilled_count;
static int hf_dash_cmpct_prefilled;
static int hf_dash_cmpct_index_diff;
static int hf_dash_cmpct_index;
static int hf_dash_cmpct_index_count;
static int hf_dash_cmpct_block_hash;
static int hf_dash_cf_filter_type;
static int hf_dash_cf_start_height;
static int hf_dash_cf_stop_hash;
static int hf_dash_cf_block_hash;
static int hf_dash_cf_filter;
static int hf_dash_cf_prev_header;
static int hf_dash_cf_count;
static int hf_dash_cf_filter_hash;
static int hf_dash_cf_header;
static int hf_dash_txrcncl_version;
static int hf_dash_txrcncl_salt;
static int hf_dash_spork_id;
static int hf_dash_spork_value;
static int hf_dash_spork_active;
static int hf_dash_spork_time_signed;
static int hf_dash_spork_sig;
static int hf_dash_spork_hash;
static int hf_dash_ssc_item;
static int hf_dash_ssc_count;
static int hf_dash_mnauth_sig;
static int hf_dash_senddsq_enabled;
static int hf_dash_qsendrecsigs_enabled;
static int hf_dash_coinjoin_denom_amount;
static int hf_dash_coinjoin_collateral;
static int hf_dash_dsa_denom;
static int hf_dash_dsa_flags;
static int hf_dash_dsa_flag_promotion;
static int hf_dash_dsa_flag_demotion;
static int hf_dash_dsi_in_count;
static int hf_dash_dsi_out_count;
static int hf_dash_dsi_out;
static int hf_dash_dsf_session_id;
static int hf_dash_dss_in_count;
static int hf_dash_dsc_session_id;
static int hf_dash_dsc_message_id;
static int hf_dash_dssu_session_id;
static int hf_dash_dssu_state;
static int hf_dash_dssu_status;
static int hf_dash_dssu_message_id;
static int hf_dash_dsq_denom;
static int hf_dash_dsq_time;
static int hf_dash_dsq_ready;
static int hf_dash_dsq_sig;
static int hf_dash_dsq_hash;
static int hf_dash_dstx_sig;
static int hf_dash_dstx_sig_time;
static int hf_dash_govsync_prop_hash;
static int hf_dash_govsync_filter;
static int hf_dash_govobj_parent_hash;
static int hf_dash_govobj_revision;
static int hf_dash_govobj_time;
static int hf_dash_govobj_collateral_hash;
static int hf_dash_govobj_data;
static int hf_dash_govobj_data_text;
static int hf_dash_govobj_type;
static int hf_dash_govobj_mn_outpoint;
static int hf_dash_govobj_sig;
static int hf_dash_govobj_hash;
static int hf_dash_govvote_mn_outpoint;
static int hf_dash_govvote_parent_hash;
static int hf_dash_govvote_outcome;
static int hf_dash_govvote_signal;
static int hf_dash_govvote_time;
static int hf_dash_govvote_sig;
static int hf_dash_govvote_hash;/* END GENERATED HF_DECL */

static int ett_dash;
static int ett_dash_payload;
static int ett_dash_varbytes;
static int ett_dash_keyid;
static int ett_dash_outpoint;
static int ett_dash_tx;
static int ett_dash_tx_in;
static int ett_dash_tx_out;
static int ett_dash_tx_payload;
static int ett_dash_bitset;
static int ett_dash_service;
static int ett_dash_netinfo;
static int ett_dash_netinfo_purpose;
static int ett_dash_netinfo_entry;
static int ett_dash_block_header;
static int ett_dash_commitment;
static int ett_dash_protx_payout;
static int ett_dash_protx_share;
static int ett_dash_services;
static int ett_dash_netaddr;
static int ett_dash_addr_entry;
static int ett_dash_inv_entry;
static int ett_dash_headers_entry;
static int ett_dash_hdr2_flags;
static int ett_dash_cmpct_prefilled;
static int ett_dash_dsa_flags;
static int ett_dash_coinjoin_collateral;
static int ett_dash_govsync_filter;
static int ett_dash_govobj_data;/* END GENERATED ETT_DECL */

static expert_field ei_dash_command_unknown;
static expert_field ei_dash_checksum_bad;
static expert_field ei_dash_trailing_data;
static expert_field ei_dash_payload_trailing;
static expert_field ei_dash_address_length;
static expert_field ei_dash_hdr2_version;
static expert_field ei_dash_coinjoin_denom_invalid;
static expert_field ei_dash_dsa_flags_invalid;
static expert_field ei_dash_govvote_sig_size;
static expert_field ei_dash_vector_too_long;
static expert_field ei_dash_govsync_hash_funcs;/* END GENERATED EI_DECL */

static bool dash_desegment = true;
static bool dash_verify_checksum = true;
static unsigned dash_default_version = DASH_PROTOCOL_VERSION;

/*
 * Per-conversation state: the protocol version announced by each side in
 * its "version" message.  Several Dash messages are serialized differently
 * depending on the negotiated (common) protocol version.
 */
typedef struct {
  address  addr[2];
  uint32_t port[2];
  uint32_t version[2];
} dash_conv_t;

/* Information handed from the framing dissector to the command dissectors */
typedef struct {
  uint32_t    magic;
  uint32_t    common_version;   /* min of both announced versions */
  dash_conv_t *conv;
} dash_pinfo_t;

/* ------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

static void
format_dash_amount(char *buf, uint64_t uvalue)
{
  int64_t  value = (int64_t)uvalue;
  uint64_t abs_value = (value < 0) ? (uint64_t)0 - uvalue : uvalue;

  snprintf(buf, ITEM_LABEL_LENGTH, "%s%" PRIu64 ".%08" PRIu64 " DASH",
           (value < 0) ? "-" : "", abs_value / 100000000, abs_value % 100000000);
}

static void
format_dash_basis_points(char *buf, uint32_t value)
{
  snprintf(buf, ITEM_LABEL_LENGTH, "%u.%02u%% (%u basis points)", value / 100, value % 100, value);
}

/* Read a CompactSize (a.k.a. varint in the Bitcoin documentation) */
static uint64_t
dash_get_compactsize(tvbuff_t *tvb, int offset, int *len)
{
  uint8_t first = tvb_get_uint8(tvb, offset);

  switch (first) {
  case 0xfd:
    *len = 3;
    return tvb_get_letohs(tvb, offset + 1);
  case 0xfe:
    *len = 5;
    return tvb_get_letohl(tvb, offset + 1);
  case 0xff:
    *len = 9;
    return tvb_get_letoh64(tvb, offset + 1);
  default:
    *len = 1;
    return first;
  }
}

/* Add a CompactSize to the tree and advance the offset */
static uint64_t
dash_add_compactsize(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset)
{
  int      len;
  uint64_t value;

  value = dash_get_compactsize(tvb, *offset, &len);
  proto_tree_add_uint64(tree, hf, tvb, *offset, len, value);
  *offset += len;
  return value;
}

/* A length must fit in what is left of the tvb */
static int
dash_check_len(tvbuff_t *tvb, int offset, uint64_t length)
{
  if (length > (uint64_t)tvb_reported_length_remaining(tvb, offset))
    THROW(ReportedBoundsError);
  return (int)length;
}

/*
 * Loops over element counts must make progress and terminate even without
 * a tree; make sure there is at least one more byte for the next element.
 */
#define DASH_LOOP_CHECK(tvb, offset) tvb_ensure_bytes_exist((tvb), (offset), 1)

/* Add a CompactSize-prefixed byte vector.  The item value is the data
 * only; the length is shown as a child. */
static proto_item *
dash_add_varbytes(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset)
{
  proto_item *ti;
  proto_tree *subtree;
  int         lenlen;
  uint64_t    len;
  int         dlen;

  len  = dash_get_compactsize(tvb, *offset, &lenlen);
  dlen = dash_check_len(tvb, *offset + lenlen, len);
  if (dlen == 0) {
    ti = proto_tree_add_bytes_format_value(tree, hf, tvb, *offset, lenlen, NULL, "<empty>");
  } else {
    ti = proto_tree_add_bytes_with_length(tree, hf, tvb, *offset, lenlen + dlen,
          tvb_get_ptr(tvb, *offset + lenlen, dlen), dlen);
  }
  subtree = proto_item_add_subtree(ti, ett_dash_varbytes);
  proto_tree_add_uint64(subtree, hf_dash_varbytes_length, tvb, *offset, lenlen, len);
  *offset += lenlen + dlen;
  return ti;
}

/* Add a CompactSize-prefixed string; returns the string */
static const char *
dash_add_varstr(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int *offset)
{
  proto_item *ti;
  proto_tree *subtree;
  int         lenlen;
  uint64_t    len;
  int         dlen;
  char       *str;

  len  = dash_get_compactsize(tvb, *offset, &lenlen);
  dlen = dash_check_len(tvb, *offset + lenlen, len);
  str = (char *)tvb_get_string_enc(pinfo->pool, tvb, *offset + lenlen, dlen, ENC_UTF_8);
  ti = proto_tree_add_string(tree, hf, tvb, *offset, lenlen + dlen, str);
  subtree = proto_item_add_subtree(ti, ett_dash_varbytes);
  proto_tree_add_uint64(subtree, hf_dash_varbytes_length, tvb, *offset, lenlen, len);
  *offset += lenlen + dlen;
  return str;
}

/* Add a little-endian hash (uint256 / uint160) in display (RPC) byte order,
 * i.e. reversed with respect to the wire. */
static proto_item *
dash_add_rhash(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset, int len)
{
  uint8_t     rev[DASH_HASH_LEN];
  proto_item *ti;
  int         i;

  DISSECTOR_ASSERT(len <= DASH_HASH_LEN);
  tvb_memcpy(tvb, rev, *offset, len);
  for (i = 0; i < len / 2; i++) {
    uint8_t tmp = rev[i];
    rev[i] = rev[len - 1 - i];
    rev[len - 1 - i] = tmp;
  }
  ti = proto_tree_add_bytes(tree, hf, tvb, *offset, len, rev);
  *offset += len;
  return ti;
}

static proto_item *
dash_add_hash(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset)
{
  return dash_add_rhash(tree, hf, tvb, offset, DASH_HASH_LEN);
}

/* Add a fixed-size item and advance */
static proto_item *
dash_add_item(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset, int len, unsigned encoding)
{
  proto_item *ti = proto_tree_add_item(tree, hf, tvb, *offset, len, encoding);
  *offset += len;
  return ti;
}

static uint32_t
dash_add_uint(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset, int len)
{
  uint32_t value;
  proto_tree_add_item_ret_uint(tree, hf, tvb, *offset, len, ENC_LITTLE_ENDIAN, &value);
  *offset += len;
  return value;
}

static int32_t
dash_add_int(proto_tree *tree, int hf, tvbuff_t *tvb, int *offset, int len)
{
  int32_t value;
  proto_tree_add_item_ret_int(tree, hf, tvb, *offset, len, ENC_LITTLE_ENDIAN, &value);
  *offset += len;
  return value;
}

/* Start a subtree item whose length is fixed up later with proto_item_set_end() */
static proto_tree *
dash_subtree(proto_tree *tree, int hf, int ett, tvbuff_t *tvb, int offset, proto_item **ti)
{
  *ti = proto_tree_add_item(tree, hf, tvb, offset, -1, ENC_NA);
  return proto_item_add_subtree(*ti, ett);
}

/* Double SHA-256 */
static void
dash_sha256d(tvbuff_t *tvb, int offset, int len, uint8_t *digest)
{
  uint8_t first[DASH_HASH_LEN];

  gcry_md_hash_buffer(GCRY_MD_SHA256, first, tvb_get_ptr(tvb, offset, len), len);
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, first, DASH_HASH_LEN);
}

/* Add a generated hash (e.g. a txid) computed as SHA256d over a range */
static proto_item *
dash_add_computed_hash(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int len)
{
  uint8_t     digest[DASH_HASH_LEN];
  uint8_t     rev[DASH_HASH_LEN];
  proto_item *ti;
  int         i;

  if (!tvb_bytes_exist(tvb, offset, len))
    return NULL;
  dash_sha256d(tvb, offset, len, digest);
  for (i = 0; i < DASH_HASH_LEN; i++)
    rev[i] = digest[DASH_HASH_LEN - 1 - i];
  ti = proto_tree_add_bytes_with_length(tree, hf, tvb, offset, len, rev, DASH_HASH_LEN);
  proto_item_set_generated(ti);
  return ti;
}

/* Hex string of a little-endian hash in display (reversed) order */
static const char *
dash_rhash_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int len)
{
  static const char hex[] = "0123456789abcdef";
  char *s = (char *)wmem_alloc(scope, (size_t)len * 2 + 1);
  int   i;

  for (i = 0; i < len; i++) {
    uint8_t b = tvb_get_uint8(tvb, offset + len - 1 - i);
    s[2 * i]     = hex[b >> 4];
    s[2 * i + 1] = hex[b & 0x0f];
  }
  s[len * 2] = '\0';
  return s;
}

/* Base58Check encoding of a version byte + 20-byte hash */
static const char *
dash_base58check(wmem_allocator_t *scope, uint8_t version, const uint8_t *hash160)
{
  static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  uint8_t  buf[25];
  uint8_t  digest[DASH_HASH_LEN];
  uint8_t  first[DASH_HASH_LEN];
  uint8_t  digits[40];
  int      ndigits = 0;
  int      zeros = 0;
  int      i, j;
  char    *out;

  buf[0] = version;
  memcpy(buf + 1, hash160, 20);
  gcry_md_hash_buffer(GCRY_MD_SHA256, first, buf, 21);
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, first, DASH_HASH_LEN);
  memcpy(buf + 21, digest, 4);

  while (zeros < 25 && buf[zeros] == 0)
    zeros++;
  for (i = zeros; i < 25; i++) {
    unsigned carry = buf[i];
    for (j = 0; j < ndigits; j++) {
      carry += (unsigned)digits[j] << 8;
      digits[j] = carry % 58;
      carry /= 58;
    }
    while (carry > 0) {
      digits[ndigits++] = carry % 58;
      carry /= 58;
    }
  }
  out = (char *)wmem_alloc(scope, (size_t)zeros + ndigits + 1);
  for (i = 0; i < zeros; i++)
    out[i] = '1';
  for (j = 0; j < ndigits; j++)
    out[zeros + j] = alphabet[digits[ndigits - 1 - j]];
  out[zeros + ndigits] = '\0';
  return out;
}

static bool
dash_is_mainnet(const dash_pinfo_t *dpi)
{
  return dpi == NULL || dpi->magic == DASH_MAGIC_MAINNET;
}

/* Add the address of a key ID (P2PKH) as a generated item */
static void
dash_add_keyid_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                       const dash_pinfo_t *dpi, bool p2sh)
{
  uint8_t     hash160[20];
  uint8_t     version;
  proto_item *ti;

  tvb_memcpy(tvb, hash160, offset, 20);
  if (dash_is_mainnet(dpi))
    version = p2sh ? 0x10 : 0x4c;
  else
    version = p2sh ? 0x13 : 0x8c;
  ti = proto_tree_add_string(tree, hf_dash_address, tvb, offset, 20,
                             dash_base58check(pinfo->pool, version, hash160));
  proto_item_set_generated(ti);
}

/* Add a CKeyID (20 bytes) with its address */
static void
dash_add_keyid(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int *offset,
               const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;

  ti = proto_tree_add_item(tree, hf, tvb, *offset, 20, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_dash_keyid);
  dash_add_keyid_address(subtree, tvb, pinfo, *offset, dpi, false);
  *offset += 20;
}

/* Classify a script and add type/address as generated items */
static void
dash_classify_script(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int len,
                     const dash_pinfo_t *dpi)
{
  unsigned    type = 0;
  proto_item *ti;

  if (len == 0) {
    type = 6;
  } else if (len == 25 && tvb_get_uint8(tvb, offset) == 0x76 && tvb_get_uint8(tvb, offset + 1) == 0xa9 &&
             tvb_get_uint8(tvb, offset + 2) == 0x14 && tvb_get_uint8(tvb, offset + 23) == 0x88 &&
             tvb_get_uint8(tvb, offset + 24) == 0xac) {
    type = 1;
  } else if (len == 23 && tvb_get_uint8(tvb, offset) == 0xa9 && tvb_get_uint8(tvb, offset + 1) == 0x14 &&
             tvb_get_uint8(tvb, offset + 22) == 0x87) {
    type = 2;
  } else if ((len == 35 && tvb_get_uint8(tvb, offset) == 33 && tvb_get_uint8(tvb, offset + 34) == 0xac) ||
             (len == 67 && tvb_get_uint8(tvb, offset) == 65 && tvb_get_uint8(tvb, offset + 66) == 0xac)) {
    type = 3;
  } else if (tvb_get_uint8(tvb, offset) == 0x6a) {
    type = 4;
  } else if (len >= 3 && tvb_get_uint8(tvb, offset + len - 1) == 0xae) {
    type = 5;
  }

  ti = proto_tree_add_uint(tree, hf_dash_script_type, tvb, offset, len, type);
  proto_item_set_generated(ti);
  if (type == 1)
    dash_add_keyid_address(tree, tvb, pinfo, offset + 3, dpi, false);
  else if (type == 2)
    dash_add_keyid_address(tree, tvb, pinfo, offset + 2, dpi, true);
}

/* Add a CScript (CompactSize length + bytes) */
static void
dash_add_script(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int *offset,
                const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;
  int         lenlen;
  uint64_t    len;

  len = dash_get_compactsize(tvb, *offset, &lenlen);
  dash_check_len(tvb, *offset + lenlen, len);
  ti = dash_add_varbytes(tree, hf, tvb, offset);
  subtree = proto_item_get_subtree(ti);
  dash_classify_script(subtree, tvb, pinfo, *offset - (int)len, (int)len, dpi);
}

/* COutPoint: hash + index (36 bytes) */
static int
dissect_dash_outpoint(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item *ti;
  proto_tree *subtree;
  uint32_t    out_index;

  ti = proto_tree_add_item(tree, hf, tvb, offset, 36, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_dash_outpoint);
  out_index = tvb_get_letohl(tvb, offset + 32);
  proto_item_append_text(ti, ": %s:%u", dash_rhash_str(pinfo->pool, tvb, offset, 32), out_index);
  dash_add_hash(subtree, hf_dash_outpoint_hash, tvb, &offset);
  dash_add_item(subtree, hf_dash_outpoint_index, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  return offset;
}

/* CTxIn */
static int
dissect_dash_txin(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, unsigned idx,
                  const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;

  subtree = dash_subtree(tree, hf_dash_tx_in, ett_dash_tx_in, tvb, offset, &ti);
  proto_item_append_text(ti, " #%u", idx);
  offset = dissect_dash_outpoint(subtree, hf_dash_tx_in_prevout, tvb, pinfo, offset);
  dash_add_varbytes(subtree, hf_dash_tx_in_script, tvb, &offset);
  dash_add_item(subtree, hf_dash_tx_in_sequence, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  (void)dpi;
  proto_item_set_end(ti, tvb, offset);
  return offset;
}

/* CTxOut */
static int
dissect_dash_txout(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset, int idx,
                   const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;
  int64_t     value;

  subtree = dash_subtree(tree, hf, ett_dash_tx_out, tvb, offset, &ti);
  if (idx >= 0)
    proto_item_append_text(ti, " #%d", idx);
  value = (int64_t)tvb_get_letoh64(tvb, offset);
  dash_add_item(subtree, hf_dash_tx_out_value, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  dash_add_script(subtree, hf_dash_tx_out_script, tvb, pinfo, &offset, dpi);
  {
    char buf[ITEM_LABEL_LENGTH];
    format_dash_amount(buf, (uint64_t)value);
    proto_item_append_text(ti, ": %s", buf);
  }
  proto_item_set_end(ti, tvb, offset);
  return offset;
}

/* DYNBITSET: CompactSize bit count + ceil(n/8) bytes, LSB first */
static int
dissect_dash_bitset(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item *ti;
  proto_tree *subtree;
  int         lenlen;
  uint64_t    nbits;
  int         nbytes;
  int         i;
  unsigned    set = 0;
  wmem_strbuf_t *members;

  nbits  = dash_get_compactsize(tvb, offset, &lenlen);
  /* bound the bit count before rounding up so a huge count cannot wrap */
  if (nbits > (uint64_t)tvb_reported_length_remaining(tvb, offset + lenlen) * 8)
    THROW(ReportedBoundsError);
  nbytes = dash_check_len(tvb, offset + lenlen, (nbits + 7) / 8);
  ti = proto_tree_add_bytes_with_length(tree, hf, tvb, offset, lenlen + nbytes,
        nbytes ? tvb_get_ptr(tvb, offset + lenlen, nbytes) : NULL, nbytes);
  subtree = proto_item_add_subtree(ti, ett_dash_bitset);
  proto_tree_add_uint64(subtree, hf_dash_bitset_size, tvb, offset, lenlen, nbits);
  members = wmem_strbuf_new(pinfo->pool, "");
  for (i = 0; i < (int)nbits; i++) {
    if (tvb_get_uint8(tvb, offset + lenlen + i / 8) & (1 << (i % 8))) {
      if (set)
        wmem_strbuf_append_c(members, ',');
      wmem_strbuf_append_printf(members, "%d", i);
      set++;
    }
  }
  ti = proto_tree_add_uint(subtree, hf_dash_bitset_count, tvb, offset + lenlen, nbytes, set);
  proto_item_set_generated(ti);
  ti = proto_tree_add_string(subtree, hf_dash_bitset_members, tvb, offset + lenlen, nbytes,
                             wmem_strbuf_get_str(members));
  proto_item_set_generated(ti);
  proto_item_append_text(proto_tree_get_parent(subtree), " (%u of %" PRIu64 " set)", set, nbits);
  return offset + lenlen + nbytes;
}

/* Legacy (v1) CService: 16-byte IPv6 (v4-mapped) + big-endian port */
static int
dissect_dash_service_v1(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item  *ti;
  proto_tree  *subtree;
  ws_in6_addr  addr;
  uint16_t     port;
  static const uint8_t v4mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };

  ti = proto_tree_add_item(tree, hf, tvb, offset, 18, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_dash_service);
  tvb_get_ipv6(tvb, offset, &addr);
  port = tvb_get_ntohs(tvb, offset + 16);
  proto_tree_add_item(subtree, hf_dash_service_ipv6, tvb, offset, 16, ENC_NA);
  if (memcmp(addr.bytes, v4mapped, 12) == 0) {
    proto_item *gi = proto_tree_add_item(subtree, hf_dash_service_ipv4, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
    proto_item_set_generated(gi);
    proto_item_append_text(ti, ": %s:%u", tvb_ip_to_str(pinfo->pool, tvb, offset + 12), port);
  } else {
    proto_item_append_text(ti, ": [%s]:%u", tvb_ip6_to_str(pinfo->pool, tvb, offset), port);
  }
  proto_tree_add_item(subtree, hf_dash_service_port, tvb, offset + 16, 2, ENC_BIG_ENDIAN);
  return offset + 18;
}

/* BIP155 (ADDRv2) CService: network id, CompactSize addr length, addr, BE port */
static int
dissect_dash_service_v2(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item *ti;
  proto_tree *subtree;
  uint8_t     network;
  int         lenlen;
  uint64_t    alen;
  int         addr_len;
  int         start = offset;
  const char *addr_str = NULL;

  subtree = dash_subtree(tree, hf, ett_dash_service, tvb, offset, &ti);
  network = tvb_get_uint8(tvb, offset);
  dash_add_item(subtree, hf_dash_service_network, tvb, &offset, 1, ENC_NA);
  alen = dash_get_compactsize(tvb, offset, &lenlen);
  addr_len = dash_check_len(tvb, offset + lenlen, alen);
  proto_tree_add_uint64(subtree, hf_dash_service_addr_len, tvb, offset, lenlen, alen);
  offset += lenlen;
  if (network == 1 && addr_len == 4) {
    proto_tree_add_item(subtree, hf_dash_service_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    addr_str = tvb_ip_to_str(pinfo->pool, tvb, offset);
  } else if ((network == 2 || network == 6) && addr_len == 16) {
    proto_tree_add_item(subtree, hf_dash_service_ipv6, tvb, offset, 16, ENC_NA);
    addr_str = wmem_strdup_printf(pinfo->pool, "[%s]", tvb_ip6_to_str(pinfo->pool, tvb, offset));
  } else {
    proto_tree_add_item(subtree, hf_dash_service_addr_other, tvb, offset, addr_len, ENC_NA);
    if ((network == 1 && addr_len != 4) || (network == 2 && addr_len != 16) ||
        ((network == 4 || network == 5) && addr_len != 32) || (network == 6 && addr_len != 16))
      proto_tree_add_expert(subtree, pinfo, &ei_dash_address_length, tvb, offset, addr_len);
  }
  offset += addr_len;
  if (addr_str)
    proto_item_append_text(ti, ": %s:%u", addr_str, tvb_get_ntohs(tvb, offset));
  else
    proto_item_append_text(ti, ": %s address", val_to_str_const(network, dash_network_ids, "Unknown"));
  dash_add_item(subtree, hf_dash_service_port, tvb, &offset, 2, ENC_BIG_ENDIAN);
  proto_item_set_len(ti, offset - start);
  return offset;
}

/*
 * Masternode network info.  MnNetInfo (ProTx/SML version < 3) is a legacy
 * 18-byte CService; ExtNetInfo (version >= 3) is a versioned map of
 * purpose -> list of entries.
 */
static int
dissect_dash_netinfo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, bool extended)
{
  proto_item *ti;
  proto_tree *subtree;
  uint8_t     version;
  uint64_t    npurposes, p;

  if (!extended)
    return dissect_dash_service_v1(tree, hf_dash_netinfo_service, tvb, pinfo, offset);

  subtree = dash_subtree(tree, hf_dash_netinfo, ett_dash_netinfo, tvb, offset, &ti);
  version = tvb_get_uint8(tvb, offset);
  dash_add_item(subtree, hf_dash_netinfo_version, tvb, &offset, 1, ENC_NA);
  if (version != 1) {
    /* Unknown/empty: nothing else is serialized */
    proto_item_set_end(ti, tvb, offset);
    return offset;
  }
  npurposes = dash_add_compactsize(subtree, hf_dash_netinfo_purpose_count, tvb, &offset);
  for (p = 0; p < npurposes; p++) {
    proto_item *pti;
    proto_tree *ptree;
    uint8_t     purpose;
    uint64_t    nentries, e;

    DASH_LOOP_CHECK(tvb, offset);
    purpose = tvb_get_uint8(tvb, offset);
    ptree = dash_subtree(subtree, hf_dash_netinfo_purpose_entry, ett_dash_netinfo_purpose, tvb, offset, &pti);
    proto_item_append_text(pti, ": %s", val_to_str_const(purpose, dash_netinfo_purposes, "Unknown"));
    dash_add_item(ptree, hf_dash_netinfo_purpose, tvb, &offset, 1, ENC_NA);
    nentries = dash_add_compactsize(ptree, hf_dash_netinfo_entry_count, tvb, &offset);
    for (e = 0; e < nentries; e++) {
      proto_item *eti;
      proto_tree *etree;
      uint8_t     etype;

      DASH_LOOP_CHECK(tvb, offset);
      etype = tvb_get_uint8(tvb, offset);
      etree = dash_subtree(ptree, hf_dash_netinfo_entry, ett_dash_netinfo_entry, tvb, offset, &eti);
      dash_add_item(etree, hf_dash_netinfo_entry_type, tvb, &offset, 1, ENC_NA);
      if (etype == 0x01) {
        offset = dissect_dash_service_v2(etree, hf_dash_netinfo_service, tvb, pinfo, offset);
      } else if (etype == 0x02) {
        const char *domain = dash_add_varstr(etree, hf_dash_netinfo_domain, tvb, pinfo, &offset);
        proto_item_append_text(eti, ": %s:%u", domain,
                               tvb_get_ntohs(tvb, offset));
        dash_add_item(etree, hf_dash_netinfo_domain_port, tvb, &offset, 2, ENC_BIG_ENDIAN);
      }
      proto_item_set_end(eti, tvb, offset);
    }
    proto_item_set_end(pti, tvb, offset);
  }
  proto_item_set_end(ti, tvb, offset);
  return offset;
}

/* 80-byte block header */
static int
dissect_dash_block_header(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
  proto_item *ti;
  proto_tree *subtree;

  ti = proto_tree_add_item(tree, hf, tvb, offset, DASH_HEADER_SIZE, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_dash_block_header);
  dash_add_item(subtree, hf_dash_block_version, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_hash(subtree, hf_dash_block_prev, tvb, &offset);
  dash_add_hash(subtree, hf_dash_block_merkle_root, tvb, &offset);
  dash_add_item(subtree, hf_dash_block_time, tvb, &offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  dash_add_item(subtree, hf_dash_block_bits, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(subtree, hf_dash_block_nonce, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  return offset;
}

/* CFinalCommitment (qfcommit message and quorum commitment tx payload) */
static int
dissect_dash_final_commitment(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item *ti;
  proto_tree *subtree;
  uint32_t    version;
  uint32_t    llmq_type;

  subtree = dash_subtree(tree, hf, ett_dash_commitment, tvb, offset, &ti);
  version = dash_add_uint(subtree, hf_dash_qc_version, tvb, &offset, 2);
  llmq_type = dash_add_uint(subtree, hf_dash_llmq_type, tvb, &offset, 1);
  dash_add_hash(subtree, hf_dash_quorum_hash, tvb, &offset);
  if (version == 2 || version == 4)
    dash_add_int(subtree, hf_dash_quorum_index, tvb, &offset, 2);
  offset = dissect_dash_bitset(subtree, hf_dash_qc_signers, tvb, pinfo, offset);
  offset = dissect_dash_bitset(subtree, hf_dash_qc_valid_members, tvb, pinfo, offset);
  dash_add_item(subtree, hf_dash_qc_quorum_pubkey, tvb, &offset, DASH_BLS_PUBKEY_LEN, ENC_NA);
  dash_add_hash(subtree, hf_dash_qc_vvec_hash, tvb, &offset);
  dash_add_item(subtree, hf_dash_qc_quorum_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  dash_add_item(subtree, hf_dash_qc_members_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  proto_item_append_text(ti, ": %s", val_to_str_const(llmq_type, dash_llmq_types, "Unknown LLMQ type"));
  proto_item_set_end(ti, tvb, offset);
  return offset;
}

/* ------------------------------------------------------------------------
 * Special transaction payloads (DIP-0002).  Each returns the new offset.
 * ------------------------------------------------------------------------ */

static int
dissect_dash_payout_shares(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                           const dash_pinfo_t *dpi)
{
  uint32_t count, i;

  count = dash_add_uint(tree, hf_dash_protx_payout_count, tvb, &offset, 1);
  for (i = 0; i < count; i++) {
    proto_item *ti;
    proto_tree *subtree;

    subtree = dash_subtree(tree, hf_dash_protx_payout, ett_dash_protx_payout, tvb, offset, &ti);
    dash_add_script(subtree, hf_dash_protx_payout_script, tvb, pinfo, &offset, dpi);
    dash_add_item(subtree, hf_dash_protx_payout_reward, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

static int
dissect_dash_protx_platform(proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t mn_type, uint32_t version)
{
  if (mn_type == 1) {
    dash_add_rhash(tree, hf_dash_protx_platform_node_id, tvb, &offset, 20);
    if (version < 3) {
      dash_add_item(tree, hf_dash_protx_platform_p2p_port, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
      dash_add_item(tree, hf_dash_protx_platform_http_port, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
    }
  }
  return offset;
}

static int
dissect_dash_proregtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  uint32_t version, mn_type, nshares, i;

  version = dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  if (version == 0 || version > 3)
    return offset;
  mn_type = dash_add_uint(tree, hf_dash_protx_mn_type, tvb, &offset, 2);
  dash_add_item(tree, hf_dash_protx_mode, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  offset = dissect_dash_outpoint(tree, hf_dash_protx_collateral, tvb, pinfo, offset);
  offset = dissect_dash_netinfo(tree, tvb, pinfo, offset, version >= 3);
  dash_add_keyid(tree, hf_dash_protx_owner_keyid, tvb, pinfo, &offset, dpi);
  dash_add_item(tree, hf_dash_protx_operator_pubkey, tvb, &offset, DASH_BLS_PUBKEY_LEN, ENC_NA);
  dash_add_keyid(tree, hf_dash_protx_voting_keyid, tvb, pinfo, &offset, dpi);
  dash_add_item(tree, hf_dash_protx_operator_reward, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  if (version < 3) {
    dash_add_script(tree, hf_dash_protx_payout_script, tvb, pinfo, &offset, dpi);
  } else {
    offset = dissect_dash_payout_shares(tree, tvb, pinfo, offset, dpi);
    nshares = dash_add_uint(tree, hf_dash_protx_share_count, tvb, &offset, 1);
    for (i = 0; i < nshares; i++) {
      proto_item *ti;
      proto_tree *subtree;

      subtree = dash_subtree(tree, hf_dash_protx_share, ett_dash_protx_share, tvb, offset, &ti);
      dash_add_item(subtree, hf_dash_protx_share_amount, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
      dash_add_script(subtree, hf_dash_protx_share_refund_script, tvb, pinfo, &offset, dpi);
      dash_add_script(subtree, hf_dash_protx_share_reward_script, tvb, pinfo, &offset, dpi);
      dash_add_keyid(subtree, hf_dash_protx_owner_keyid, tvb, pinfo, &offset, dpi);
      proto_item_set_end(ti, tvb, offset);
    }
    for (i = 0; i < nshares; i++)
      dash_add_item(tree, hf_dash_protx_join_sig, tvb, &offset, 65, ENC_NA);
    dash_add_item(tree, hf_dash_protx_early_period, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
    dash_add_item(tree, hf_dash_protx_early_penalty, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  }
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  offset = dissect_dash_protx_platform(tree, tvb, offset, mn_type, version);
  dash_add_varbytes(tree, hf_dash_protx_sig, tvb, &offset);
  return offset;
}

static int
dissect_dash_proupservtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  uint32_t version, mn_type = 0;

  version = dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  if (version == 0 || version > 3)
    return offset;
  if (version >= 2)
    mn_type = dash_add_uint(tree, hf_dash_protx_mn_type, tvb, &offset, 2);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  offset = dissect_dash_netinfo(tree, tvb, pinfo, offset, version >= 3);
  dash_add_script(tree, hf_dash_protx_operator_payout_script, tvb, pinfo, &offset, dpi);
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  offset = dissect_dash_protx_platform(tree, tvb, offset, mn_type, version);
  dash_add_item(tree, hf_dash_protx_bls_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  return offset;
}

static int
dissect_dash_proupregtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  uint32_t version;

  version = dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  if (version == 0 || version > 3)
    return offset;
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_mode, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_protx_operator_pubkey, tvb, &offset, DASH_BLS_PUBKEY_LEN, ENC_NA);
  dash_add_keyid(tree, hf_dash_protx_voting_keyid, tvb, pinfo, &offset, dpi);
  if (version < 3)
    dash_add_script(tree, hf_dash_protx_payout_script, tvb, pinfo, &offset, dpi);
  else
    offset = dissect_dash_payout_shares(tree, tvb, pinfo, offset, dpi);
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  dash_add_varbytes(tree, hf_dash_protx_sig, tvb, &offset);
  return offset;
}

static int
dissect_dash_prouprevtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, const dash_pinfo_t *dpi _U_)
{
  uint32_t version;

  version = dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  if (version == 0 || version > 3)
    return offset;
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_revoke_reason, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_bls_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  return offset;
}

static int
dissect_dash_prodistx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, const dash_pinfo_t *dpi _U_)
{
  uint32_t count, i;

  dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_actor_index, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  count = dash_add_uint(tree, hf_dash_protx_sig_count, tvb, &offset, 1);
  for (i = 0; i < count; i++)
    dash_add_item(tree, hf_dash_protx_compact_sig, tvb, &offset, 65, ENC_NA);
  return offset;
}

static int
dissect_dash_proupsharetx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_share_index, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  dash_add_script(tree, hf_dash_protx_share_reward_script, tvb, pinfo, &offset, dpi);
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  dash_add_varbytes(tree, hf_dash_protx_sig, tvb, &offset);
  return offset;
}

static int
dissect_dash_proupsharedregtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  uint32_t count, i;

  dash_add_uint(tree, hf_dash_protx_version, tvb, &offset, 2);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_protx_operator_pubkey, tvb, &offset, DASH_BLS_PUBKEY_LEN, ENC_NA);
  dash_add_keyid(tree, hf_dash_protx_voting_keyid, tvb, pinfo, &offset, dpi);
  dash_add_hash(tree, hf_dash_protx_inputs_hash, tvb, &offset);
  count = dash_add_uint(tree, hf_dash_protx_sig_count, tvb, &offset, 1);
  for (i = 0; i < count; i++)
    dash_add_item(tree, hf_dash_protx_compact_sig, tvb, &offset, 65, ENC_NA);
  return offset;
}

static int
dissect_dash_cbtx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, const dash_pinfo_t *dpi _U_)
{
  uint32_t version;

  version = dash_add_uint(tree, hf_dash_cbtx_version, tvb, &offset, 2);
  dash_add_item(tree, hf_dash_cbtx_height, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_hash(tree, hf_dash_cbtx_merkle_mnlist, tvb, &offset);
  if (version >= 2)
    dash_add_hash(tree, hf_dash_cbtx_merkle_quorums, tvb, &offset);
  if (version >= 3) {
    dash_add_compactsize(tree, hf_dash_cbtx_best_cl_height_diff, tvb, &offset);
    dash_add_item(tree, hf_dash_cbtx_best_cl_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
    dash_add_item(tree, hf_dash_cbtx_credit_pool, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  }
  if (version >= 4)
    dash_add_hash(tree, hf_dash_cbtx_merkle_asset_unlocks, tvb, &offset);
  return offset;
}

static int
dissect_dash_qctx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi _U_)
{
  dash_add_item(tree, hf_dash_qctx_version, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_qctx_height, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  return dissect_dash_final_commitment(tree, hf_dash_commitment, tvb, pinfo, offset);
}

static int
dissect_dash_mnhftx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, const dash_pinfo_t *dpi _U_)
{
  dash_add_item(tree, hf_dash_mnhf_version, tvb, &offset, 1, ENC_NA);
  dash_add_item(tree, hf_dash_mnhf_version_bit, tvb, &offset, 1, ENC_NA);
  dash_add_hash(tree, hf_dash_quorum_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_mnhf_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  return offset;
}

static int
dissect_dash_assetlocktx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, const dash_pinfo_t *dpi)
{
  uint64_t count, i;

  dash_add_item(tree, hf_dash_asset_version, tvb, &offset, 1, ENC_NA);
  count = dash_add_compactsize(tree, hf_dash_assetlock_output_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txout(tree, hf_dash_assetlock_output, tvb, pinfo, offset, (int)i, dpi);
  }
  return offset;
}

static int
dissect_dash_assetunlocktx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, const dash_pinfo_t *dpi _U_)
{
  dash_add_item(tree, hf_dash_asset_version, tvb, &offset, 1, ENC_NA);
  dash_add_item(tree, hf_dash_assetunlock_index, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_assetunlock_fee, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_assetunlock_requested_height, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_hash(tree, hf_dash_quorum_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_assetunlock_quorum_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  return offset;
}

typedef int (*dash_payload_fn)(proto_tree *, tvbuff_t *, packet_info *, int, const dash_pinfo_t *);

static const dash_payload_fn dash_payload_dissectors[] = {
  NULL,                           /* 0 normal */
  dissect_dash_proregtx,          /* 1 */
  dissect_dash_proupservtx,       /* 2 */
  dissect_dash_proupregtx,        /* 3 */
  dissect_dash_prouprevtx,        /* 4 */
  dissect_dash_cbtx,              /* 5 */
  dissect_dash_qctx,              /* 6 */
  dissect_dash_mnhftx,            /* 7 */
  dissect_dash_assetlocktx,       /* 8 */
  dissect_dash_assetunlocktx,     /* 9 */
  dissect_dash_prodistx,          /* 10 */
  dissect_dash_proupsharetx,      /* 11 */
  dissect_dash_proupsharedregtx,  /* 12 */
};

/* Dissect a vExtraPayload of the given type (offset points at the CompactSize) */
static int
dissect_dash_extra_payload(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                           uint32_t type, const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;
  int         lenlen;
  uint64_t    len;
  int         plen;
  tvbuff_t   *ptvb;
  int         consumed;

  len  = dash_get_compactsize(tvb, offset, &lenlen);
  plen = dash_check_len(tvb, offset + lenlen, len);
  ti = proto_tree_add_item(tree, hf_dash_tx_payload, tvb, offset, lenlen + plen, ENC_NA);
  proto_item_append_text(ti, ": %s", val_to_str_const(type, dash_tx_types, "Unknown type"));
  subtree = proto_item_add_subtree(ti, ett_dash_tx_payload);
  proto_tree_add_uint64(subtree, hf_dash_tx_payload_size, tvb, offset, lenlen, len);
  offset += lenlen;

  if (type < array_length(dash_payload_dissectors) && dash_payload_dissectors[type] != NULL) {
    ptvb = tvb_new_subset_length(tvb, offset, plen);
    consumed = dash_payload_dissectors[type](subtree, ptvb, pinfo, 0, dpi);
    if (consumed < plen)
      proto_tree_add_expert(subtree, pinfo, &ei_dash_payload_trailing, ptvb, consumed, plen - consumed);
  } else {
    proto_tree_add_item(subtree, hf_dash_tx_payload_data, tvb, offset, plen, ENC_NA);
  }
  return offset + plen;
}

/*
 * Dissect a transaction starting at offset.  idx >= 0 numbers the
 * transaction inside a block.  Returns the offset after the transaction.
 */
static int
dissect_dash_tx(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int idx,
                const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;
  int         start = offset;
  uint32_t    packed;
  int16_t     version;
  uint16_t    type;
  uint64_t    count, i;
  bool        has_payload;

  subtree = dash_subtree(tree, hf_dash_tx, ett_dash_tx, tvb, offset, &ti);
  if (idx >= 0)
    proto_item_append_text(ti, " #%d", idx);

  packed  = tvb_get_letohl(tvb, offset);
  version = (int16_t)(packed & 0xffff);
  type    = (uint16_t)(packed >> 16);
  proto_tree_add_item(subtree, hf_dash_tx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_dash_tx_type, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
  offset += 4;
  has_payload = (version >= 3 && type != 0);

  count = dash_add_compactsize(subtree, hf_dash_tx_in_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txin(subtree, tvb, pinfo, offset, (unsigned)i, dpi);
  }
  count = dash_add_compactsize(subtree, hf_dash_tx_out_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txout(subtree, hf_dash_tx_out, tvb, pinfo, offset, (int)i, dpi);
  }
  dash_add_item(subtree, hf_dash_tx_lock_time, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  if (has_payload)
    offset = dissect_dash_extra_payload(subtree, tvb, pinfo, offset, type, dpi);

  proto_item_set_end(ti, tvb, offset);

  /* txid = SHA256d of the serialization.  Version 2+ asset unlocks hash
   * with the quorum info (last 132 bytes) zeroed, see transaction.cpp. */
  if (tvb_bytes_exist(tvb, start, offset - start)) {
    uint8_t     digest[DASH_HASH_LEN], first[DASH_HASH_LEN], rev[DASH_HASH_LEN];
    int         len = offset - start;
    int         j;
    uint8_t    *buf;
    proto_item *hti;
    bool        stable = false;

    /* payload is exactly 145 bytes (CompactSize 0x91) and its version >= 2 */
    if (has_payload && type == 9 && len > 146 &&
        tvb_get_uint8(tvb, offset - 146) == 145 && tvb_get_uint8(tvb, offset - 145) >= 2)
      stable = true;

    buf = (uint8_t *)tvb_memdup(pinfo->pool, tvb, start, len);
    if (stable)
      memset(buf + len - 132, 0, 132);
    gcry_md_hash_buffer(GCRY_MD_SHA256, first, buf, len);
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, first, DASH_HASH_LEN);
    for (j = 0; j < DASH_HASH_LEN; j++)
      rev[j] = digest[DASH_HASH_LEN - 1 - j];
    hti = proto_tree_add_bytes_with_length(subtree, hf_dash_tx_txid, tvb, start, len, rev, DASH_HASH_LEN);
    proto_item_set_generated(hti);
    proto_item_append_text(ti, ", txid %s", bytes_to_str_maxlen(pinfo->pool, rev, DASH_HASH_LEN, 0));
    if (stable)
      dash_add_computed_hash(subtree, hf_dash_tx_instance_hash, tvb, start, len);
  }
  if (type != 0)
    proto_item_append_text(ti, " (%s)", val_to_str_const(type, dash_tx_types, "Unknown type"));
  return offset;
}

/* ------------------------------------------------------------------------
 * Message dissectors shared with Bitcoin (with Dash differences)
 * Each handler gets the payload tvb, a tree for the payload, and a
 * dash_pinfo_t * as data; it returns the number of bytes it dissected.
 * ------------------------------------------------------------------------ */

static int * const dash_services_flags[] = {
  &hf_dash_services_network,
  &hf_dash_services_bloom,
  &hf_dash_services_compact_filters,
  &hf_dash_services_network_limited,
  &hf_dash_services_headers_compressed,
  &hf_dash_services_p2p_v2,
  NULL
};

/* Find (or assign) the side of the conversation the packet comes from */
static int
dash_conv_direction(dash_conv_t *conv, packet_info *pinfo)
{
  int i;

  for (i = 0; i < 2; i++) {
    if (conv->addr[i].type != AT_NONE && conv->port[i] == pinfo->srcport &&
        addresses_equal(&conv->addr[i], &pinfo->src))
      return i;
  }
  for (i = 0; i < 2; i++) {
    if (conv->addr[i].type == AT_NONE) {
      copy_address_wmem(wmem_file_scope(), &conv->addr[i], &pinfo->src);
      conv->port[i] = pinfo->srcport;
      return i;
    }
  }
  return 0;
}

/* net_addr without timestamp: services, IPv6, port (26 bytes) */
static int
dissect_dash_netaddr(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
  proto_item *ti;
  proto_tree *subtree;

  ti = proto_tree_add_item(tree, hf, tvb, offset, 26, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_dash_netaddr);
  proto_tree_add_bitmask(subtree, tvb, offset, hf_dash_services, ett_dash_services,
                         dash_services_flags, ENC_LITTLE_ENDIAN);
  offset += 8;
  offset = dissect_dash_service_v1(subtree, hf_dash_netinfo_service, tvb, pinfo, offset);
  return offset;
}

static int
dissect_dash_msg_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  dash_pinfo_t *dpi = (dash_pinfo_t *)data;
  int           offset = 0;
  uint32_t      version;
  const char   *agent;

  version = dash_add_uint(tree, hf_dash_version_version, tvb, &offset, 4);
  if (dpi && dpi->conv && !PINFO_FD_VISITED(pinfo))
    dpi->conv->version[dash_conv_direction(dpi->conv, pinfo)] = version;
  proto_tree_add_bitmask(tree, tvb, offset, hf_dash_services, ett_dash_services,
                         dash_services_flags, ENC_LITTLE_ENDIAN);
  offset += 8;
  dash_add_item(tree, hf_dash_version_timestamp, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  offset = dissect_dash_netaddr(tree, hf_dash_version_addr_recv, tvb, pinfo, offset);
  offset = dissect_dash_netaddr(tree, hf_dash_version_addr_from, tvb, pinfo, offset);
  dash_add_item(tree, hf_dash_version_nonce, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  agent = dash_add_varstr(tree, hf_dash_version_user_agent, tvb, pinfo, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%u, %s)", version, agent);
  dash_add_item(tree, hf_dash_version_start_height, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  if (tvb_reported_length_remaining(tvb, offset) >= 1)
    dash_add_item(tree, hf_dash_version_relay, tvb, &offset, 1, ENC_NA);
  if (tvb_reported_length_remaining(tvb, offset) >= DASH_HASH_LEN)
    dash_add_hash(tree, hf_dash_version_mnauth_challenge, tvb, &offset);
  if (tvb_reported_length_remaining(tvb, offset) >= 1)
    dash_add_item(tree, hf_dash_version_masternode, tvb, &offset, 1, ENC_NA);
  return offset;
}

static int
dissect_dash_msg_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  count = dash_add_compactsize(tree, hf_dash_addr_count, tvb, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 ")", count);
  for (i = 0; i < count; i++) {
    proto_item *ti;
    proto_tree *subtree;

    DASH_LOOP_CHECK(tvb, offset);
    subtree = dash_subtree(tree, hf_dash_addr_entry, ett_dash_addr_entry, tvb, offset, &ti);
    dash_add_item(subtree, hf_dash_addr_timestamp, tvb, &offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, offset, hf_dash_services, ett_dash_services,
                           dash_services_flags, ENC_LITTLE_ENDIAN);
    offset += 8;
    offset = dissect_dash_service_v1(subtree, hf_dash_netinfo_service, tvb, pinfo, offset);
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

static int
dissect_dash_msg_addrv2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  count = dash_add_compactsize(tree, hf_dash_addr_count, tvb, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 ")", count);
  for (i = 0; i < count; i++) {
    proto_item *ti, *sti;
    proto_tree *subtree;
    int         len;
    uint64_t    services;

    DASH_LOOP_CHECK(tvb, offset);
    subtree = dash_subtree(tree, hf_dash_addr_entry, ett_dash_addr_entry, tvb, offset, &ti);
    dash_add_item(subtree, hf_dash_addr_timestamp, tvb, &offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    services = dash_get_compactsize(tvb, offset, &len);
    sti = proto_tree_add_bitmask_value(subtree, tvb, offset, hf_dash_services, ett_dash_services,
                                       dash_services_flags, services);
    proto_item_set_len(sti, len);
    offset += len;
    offset = dissect_dash_service_v2(subtree, hf_dash_netinfo_service, tvb, pinfo, offset);
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

/* inv / getdata / notfound */
static int
dissect_dash_msg_inv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  count = dash_add_compactsize(tree, hf_dash_inv_count, tvb, &offset);
  if (count == 1)
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_ext_const(tvb_get_letohl(tvb, offset), &dash_inv_types_ext, "unknown"));
  else
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 ")", count);
  for (i = 0; i < count; i++) {
    proto_item *ti;
    proto_tree *subtree;
    uint32_t    type;

    tvb_ensure_bytes_exist(tvb, offset, 36);
    type = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_item(tree, hf_dash_inv_entry, tvb, offset, 36, ENC_NA);
    proto_item_append_text(ti, ": %s %s", val_to_str_ext_const(type, &dash_inv_types_ext, "Unknown"),
                           dash_rhash_str(pinfo->pool, tvb, offset + 4, 32));
    subtree = proto_item_add_subtree(ti, ett_dash_inv_entry);
    dash_add_item(subtree, hf_dash_inv_type, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
    dash_add_hash(subtree, hf_dash_inv_hash, tvb, &offset);
  }
  return offset;
}

/* getblocks / getheaders / getheaders2: CBlockLocator + hashStop */
static int
dissect_dash_msg_getheaders(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  dash_add_item(tree, hf_dash_locator_version, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  count = dash_add_compactsize(tree, hf_dash_locator_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    tvb_ensure_bytes_exist(tvb, offset, DASH_HASH_LEN);
    dash_add_hash(tree, hf_dash_locator_hash, tvb, &offset);
  }
  dash_add_hash(tree, hf_dash_locator_stop, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  count = dash_add_compactsize(tree, hf_dash_headers_count, tvb, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 ")", count);
  for (i = 0; i < count; i++) {
    proto_item *ti;
    proto_tree *subtree;

    tvb_ensure_bytes_exist(tvb, offset, DASH_HEADER_SIZE + 1);
    subtree = dash_subtree(tree, hf_dash_headers_entry, ett_dash_headers_entry, tvb, offset, &ti);
    proto_item_append_text(ti, " #%" PRIu64, i);
    offset = dissect_dash_block_header(subtree, hf_dash_block_header, tvb, pinfo, offset);
    dash_add_compactsize(subtree, hf_dash_headers_tx_count, tvb, &offset);
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

/* headers2: DIP-0025 compressed block headers */
static int * const dash_hdr2_flags[] = {
  &hf_dash_hdr2_flag_version,
  &hf_dash_hdr2_flag_prev,
  &hf_dash_hdr2_flag_time,
  &hf_dash_hdr2_flag_bits,
  NULL
};

static int
dissect_dash_msg_headers2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;
  int32_t  versions[7];
  int      nversions = 0;
  uint32_t prev_time = 0, prev_bits = 0;

  count = dash_add_compactsize(tree, hf_dash_headers_count, tvb, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 ")", count);
  for (i = 0; i < count; i++) {
    proto_item *ti, *gi;
    proto_tree *subtree;
    uint8_t     flags;
    int         voff;
    int32_t     version = 0;
    uint32_t    hdr_time, bits;
    int         j;

    DASH_LOOP_CHECK(tvb, offset);
    subtree = dash_subtree(tree, hf_dash_headers_entry, ett_dash_headers_entry, tvb, offset, &ti);
    proto_item_append_text(ti, " #%" PRIu64, i);
    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(subtree, tvb, offset, hf_dash_hdr2_flags, ett_dash_hdr2_flags,
                           dash_hdr2_flags, ENC_NA);
    offset += 1;

    voff = flags & 0x07;
    if (voff == 0) {
      version = (int32_t)tvb_get_letohl(tvb, offset);
      dash_add_item(subtree, hf_dash_block_version, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
      /* push to front, evicting the oldest */
      if (nversions == 7)
        nversions--;
      memmove(&versions[1], &versions[0], nversions * sizeof(versions[0]));
      versions[0] = version;
      nversions++;
    } else if (i > 0 && voff <= nversions) {
      version = versions[voff - 1];
      for (j = voff - 1; j > 0; j--)
        versions[j] = versions[j - 1];
      versions[0] = version;
      gi = proto_tree_add_uint(subtree, hf_dash_block_version, tvb, offset - 1, 1, (uint32_t)version);
      proto_item_set_generated(gi);
    } else {
      proto_tree_add_expert(subtree, pinfo, &ei_dash_hdr2_version, tvb, offset - 1, 1);
    }

    if (flags & 0x08)
      dash_add_hash(subtree, hf_dash_block_prev, tvb, &offset);
    dash_add_hash(subtree, hf_dash_block_merkle_root, tvb, &offset);

    if (flags & 0x10) {
      hdr_time = tvb_get_letohl(tvb, offset);
      dash_add_item(subtree, hf_dash_block_time, tvb, &offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    } else {
      int16_t delta = (int16_t)tvb_get_letohs(tvb, offset);
      nstime_t ts;

      dash_add_item(subtree, hf_dash_hdr2_time_offset, tvb, &offset, 2, ENC_LITTLE_ENDIAN);
      hdr_time = prev_time + (uint32_t)(int32_t)delta;
      ts.secs = hdr_time;
      ts.nsecs = 0;
      gi = proto_tree_add_time(subtree, hf_dash_block_time, tvb, offset - 2, 2, &ts);
      proto_item_set_generated(gi);
    }

    if (flags & 0x20) {
      bits = tvb_get_letohl(tvb, offset);
      dash_add_item(subtree, hf_dash_block_bits, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
    } else {
      bits = prev_bits;
      gi = proto_tree_add_uint(subtree, hf_dash_block_bits, tvb, offset, 0, bits);
      proto_item_set_generated(gi);
    }
    dash_add_item(subtree, hf_dash_block_nonce, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
    prev_time = hdr_time;
    prev_bits = bits;
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

static int
dissect_dash_msg_tx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  return dissect_dash_tx(tree, tvb, pinfo, 0, -1, (dash_pinfo_t *)data);
}

static int
dissect_dash_msg_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int      offset = 0;
  uint64_t count, i;

  offset = dissect_dash_block_header(tree, hf_dash_block_header, tvb, pinfo, offset);
  count = dash_add_compactsize(tree, hf_dash_block_tx_count, tvb, &offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 " tx)", count);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_tx(tree, tvb, pinfo, offset, (int)i, (dash_pinfo_t *)data);
  }
  return offset;
}

static int
dissect_dash_msg_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_ping_nonce, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  return offset;
}

static int
dissect_dash_msg_filterload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_varbytes(tree, hf_dash_filter_data, tvb, &offset);
  dash_add_item(tree, hf_dash_filter_hash_funcs, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_filter_tweak, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_filter_flags, tvb, &offset, 1, ENC_NA);
  return offset;
}

static int
dissect_dash_msg_filteradd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_varbytes(tree, hf_dash_filter_data, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_merkleblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  offset = dissect_dash_block_header(tree, hf_dash_block_header, tvb, pinfo, offset);
  dash_add_item(tree, hf_dash_merkle_total_tx, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  count = dash_add_compactsize(tree, hf_dash_merkle_hash_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    tvb_ensure_bytes_exist(tvb, offset, DASH_HASH_LEN);
    dash_add_hash(tree, hf_dash_merkle_hash, tvb, &offset);
  }
  dash_add_varbytes(tree, hf_dash_merkle_flags, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_sendcmpct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_cmpct_announce, tvb, &offset, 1, ENC_NA);
  dash_add_item(tree, hf_dash_cmpct_version, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  return offset;
}

static int
dissect_dash_msg_cmpctblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int      offset = 0;
  uint64_t count, i;
  int64_t  last = -1;

  offset = dissect_dash_block_header(tree, hf_dash_block_header, tvb, pinfo, offset);
  dash_add_item(tree, hf_dash_cmpct_nonce, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  count = dash_add_compactsize(tree, hf_dash_cmpct_shortid_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    tvb_ensure_bytes_exist(tvb, offset, 6);
    dash_add_item(tree, hf_dash_cmpct_shortid, tvb, &offset, 6, ENC_LITTLE_ENDIAN);
  }
  count = dash_add_compactsize(tree, hf_dash_cmpct_prefilled_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    proto_item *ti, *gi;
    proto_tree *subtree;
    uint64_t    diff;

    DASH_LOOP_CHECK(tvb, offset);
    subtree = dash_subtree(tree, hf_dash_cmpct_prefilled, ett_dash_cmpct_prefilled, tvb, offset, &ti);
    diff = dash_add_compactsize(subtree, hf_dash_cmpct_index_diff, tvb, &offset);
    last = last + (int64_t)diff + 1;
    gi = proto_tree_add_uint64(subtree, hf_dash_cmpct_index, tvb, offset, 0, (uint64_t)last);
    proto_item_set_generated(gi);
    offset = dissect_dash_tx(subtree, tvb, pinfo, offset, -1, (dash_pinfo_t *)data);
    proto_item_set_end(ti, tvb, offset);
  }
  return offset;
}

static int
dissect_dash_msg_getblocktxn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;
  int64_t  last = -1;

  dash_add_hash(tree, hf_dash_cmpct_block_hash, tvb, &offset);
  count = dash_add_compactsize(tree, hf_dash_cmpct_index_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    proto_item *gi;
    uint64_t    diff;

    DASH_LOOP_CHECK(tvb, offset);
    diff = dash_add_compactsize(tree, hf_dash_cmpct_index_diff, tvb, &offset);
    last = last + (int64_t)diff + 1;
    gi = proto_tree_add_uint64(tree, hf_dash_cmpct_index, tvb, offset, 0, (uint64_t)last);
    proto_item_set_generated(gi);
  }
  return offset;
}

static int
dissect_dash_msg_blocktxn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int      offset = 0;
  uint64_t count, i;

  dash_add_hash(tree, hf_dash_cmpct_block_hash, tvb, &offset);
  count = dash_add_compactsize(tree, hf_dash_block_tx_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_tx(tree, tvb, pinfo, offset, (int)i, (dash_pinfo_t *)data);
  }
  return offset;
}

/* BIP157 compact block filters */
static int
dissect_dash_msg_getcfilters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_cf_filter_type, tvb, &offset, 1, ENC_NA);
  dash_add_item(tree, hf_dash_cf_start_height, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_hash(tree, hf_dash_cf_stop_hash, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_cfilter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_cf_filter_type, tvb, &offset, 1, ENC_NA);
  dash_add_hash(tree, hf_dash_cf_block_hash, tvb, &offset);
  dash_add_varbytes(tree, hf_dash_cf_filter, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_getcfcheckpt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_cf_filter_type, tvb, &offset, 1, ENC_NA);
  dash_add_hash(tree, hf_dash_cf_stop_hash, tvb, &offset);
  return offset;
}

static int
dissect_dash_msg_cfheaders(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  dash_add_item(tree, hf_dash_cf_filter_type, tvb, &offset, 1, ENC_NA);
  dash_add_hash(tree, hf_dash_cf_stop_hash, tvb, &offset);
  dash_add_hash(tree, hf_dash_cf_prev_header, tvb, &offset);
  count = dash_add_compactsize(tree, hf_dash_cf_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    tvb_ensure_bytes_exist(tvb, offset, DASH_HASH_LEN);
    dash_add_hash(tree, hf_dash_cf_filter_hash, tvb, &offset);
  }
  return offset;
}

static int
dissect_dash_msg_cfcheckpt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int      offset = 0;
  uint64_t count, i;

  dash_add_item(tree, hf_dash_cf_filter_type, tvb, &offset, 1, ENC_NA);
  dash_add_hash(tree, hf_dash_cf_stop_hash, tvb, &offset);
  count = dash_add_compactsize(tree, hf_dash_cf_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    tvb_ensure_bytes_exist(tvb, offset, DASH_HASH_LEN);
    dash_add_hash(tree, hf_dash_cf_header, tvb, &offset);
  }
  return offset;
}

static int
dissect_dash_msg_sendtxrcncl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_txrcncl_version, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(tree, hf_dash_txrcncl_salt, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  return offset;
}

static int
dissect_dash_msg_empty(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
  return 0;
}

/* ------------------------------------------------------------------------
 * Framing
 * ------------------------------------------------------------------------ */

static unsigned
get_dash_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint32_t payload_length = tvb_get_letohl(tvb, offset + 16);

  if (payload_length > UINT32_MAX - DASH_HEADER_LENGTH)
    return UINT32_MAX;
  return DASH_HEADER_LENGTH + payload_length;
}

static int
dissect_dash_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item        *ti, *pti;
  proto_tree        *dash_tree, *payload_tree;
  const uint8_t     *command;
  dissector_handle_t command_handle;
  uint32_t           payload_len;
  tvbuff_t          *payload_tvb;
  conversation_t    *conversation;
  dash_pinfo_t       dpi;
  int                consumed;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Dash");

  ti = proto_tree_add_item(tree, proto_dash, tvb, 0, -1, ENC_NA);
  dash_tree = proto_item_add_subtree(ti, ett_dash);

  dpi.magic = tvb_get_ntohl(tvb, 0);
  proto_tree_add_item(dash_tree, hf_dash_magic, tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_string(dash_tree, hf_dash_command, tvb, 4, 12, ENC_ASCII|ENC_NA,
                                 pinfo->pool, &command);
  proto_tree_add_item_ret_uint(dash_tree, hf_dash_length, tvb, 16, 4, ENC_LITTLE_ENDIAN, &payload_len);

  payload_tvb = tvb_new_subset_remaining(tvb, DASH_HEADER_LENGTH);
  if (dash_verify_checksum && tvb_bytes_exist(tvb, DASH_HEADER_LENGTH, payload_len)) {
    uint8_t digest[DASH_HASH_LEN];
    dash_sha256d(tvb, DASH_HEADER_LENGTH, payload_len, digest);
    proto_tree_add_checksum(dash_tree, tvb, 20, hf_dash_checksum, hf_dash_checksum_status,
                            &ei_dash_checksum_bad, pinfo, pntohu32(digest), ENC_BIG_ENDIAN,
                            PROTO_CHECKSUM_VERIFY);
  } else {
    proto_tree_add_checksum(dash_tree, tvb, 20, hf_dash_checksum, hf_dash_checksum_status,
                            &ei_dash_checksum_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
  }

  conversation = find_or_create_conversation(pinfo);
  dpi.conv = (dash_conv_t *)conversation_get_proto_data(conversation, proto_dash);
  if (!dpi.conv) {
    dpi.conv = wmem_new0(wmem_file_scope(), dash_conv_t);
    conversation_add_proto_data(conversation, proto_dash, dpi.conv);
  }
  {
    uint32_t v0 = dpi.conv->version[0] ? dpi.conv->version[0] : dash_default_version;
    uint32_t v1 = dpi.conv->version[1] ? dpi.conv->version[1] : dash_default_version;
    dpi.common_version = MIN(v0, v1);
  }

  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", (const char *)command);
  proto_item_append_text(ti, ", %s", command);

  command_handle = dissector_get_string_handle(dash_command_table, (const char *)command);
  if (payload_len > 0) {
    pti = proto_tree_add_item(dash_tree, hf_dash_payload, tvb, DASH_HEADER_LENGTH, -1, ENC_NA);
    proto_item_append_text(pti, " (%s)", command);
    payload_tree = proto_item_add_subtree(pti, ett_dash_payload);
  } else {
    payload_tree = dash_tree;
  }

  if (command_handle == NULL) {
    expert_add_info(pinfo, ti, &ei_dash_command_unknown);
    proto_tree_add_item(payload_tree, hf_dash_payload_data, payload_tvb, 0, -1, ENC_NA);
    return tvb_reported_length(tvb);
  }

  consumed = call_dissector_only(command_handle, payload_tvb, pinfo, payload_tree, &dpi);
  if (consumed >= 0 && (unsigned)consumed < payload_len)
    proto_tree_add_expert(payload_tree, pinfo, &ei_dash_trailing_data, payload_tvb, consumed,
                          payload_len - consumed);

  return tvb_reported_length(tvb);
}

static int
dissect_dash(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, dash_desegment, DASH_HEADER_LENGTH,
                   get_dash_pdu_length, dissect_dash_tcp_pdu, data);
  return tvb_reported_length(tvb);
}

static bool
dash_is_magic(uint32_t magic)
{
  return magic == DASH_MAGIC_MAINNET || magic == DASH_MAGIC_TESTNET ||
         magic == DASH_MAGIC_DEVNET  || magic == DASH_MAGIC_REGTEST;
}

static bool
dissect_dash_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  conversation_t *conversation;
  int             i;
  bool            nul = false;

  if (tvb_captured_length(tvb) < DASH_HEADER_LENGTH)
    return false;
  if (!dash_is_magic(tvb_get_ntohl(tvb, 0)))
    return false;
  /* command: printable ASCII, NUL padded */
  for (i = 0; i < 12; i++) {
    uint8_t c = tvb_get_uint8(tvb, 4 + i);
    if (c == 0) {
      nul = true;
    } else if (nul || c < 0x20 || c > 0x7e) {
      return false;
    }
  }

  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, dash_handle);
  dissect_dash(tvb, pinfo, tree, data);
  return true;
}

/* Register a command dissector */
static void
dash_add_command(const char *command, dissector_t fn)
{
  dissector_add_string("dash.command", command, create_dissector_handle(fn, proto_dash));
}

/* ------------------------------------------------------------------------
 * Fragment: coinjoin_gov
 * Sporks, sync status count, mnauth, simple flag messages, CoinJoin and
 * governance.  Wire formats from Dash Core v24.0.1 (src/ paths below).
 * ------------------------------------------------------------------------ */

/* version.h:73 - dsa carries nFlags only at or above this version */
#define DASH_COINJOIN_REBALANCE_VERSION 70241

/* coinjoin/common.h:41-47 vecStandardDenominations (duffs) */
static const int64_t dash_cj_denominations[] = {
  1000010000,  /* 10.0001 DASH */
   100001000,  /* 1.00001 */
    10000100,  /* 0.100001 */
     1000010,  /* 0.0100001 */
      100001   /* 0.00100001 */
};

/* coinjoin/common.h:31-44 GetMaxPoolInputOutputCount():
 * nPoolMaxParticipants(20) * COINJOIN_ENTRY_MAX_SIZE(9) */

/* spork.h:34-43 (current) plus retired IDs from earlier spork.h versions
 * (git history v0.12.1 - v23); the rule is id = 9999 + N for SPORK_N. */
static const value_string dash_spork_ids[] = {
  { 10001, "SPORK_2_INSTANTSEND_ENABLED" },
  { 10002, "SPORK_3_INSTANTSEND_BLOCK_FILTERING (retired)" },
  { 10004, "SPORK_5_INSTANTSEND_MAX_VALUE (retired)" },
  { 10005, "SPORK_6_NEW_SIGS (retired)" },
  { 10007, "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT (retired)" },
  { 10008, "SPORK_9_SUPERBLOCKS_ENABLED (retired)" },
  { 10009, "SPORK_10_MASTERNODE_PAY_UPDATED_NODES (retired)" },
  { 10011, "SPORK_12_RECONSIDER_BLOCKS (retired)" },
  { 10012, "SPORK_13_OLD_SUPERBLOCK_FLAG (retired)" },
  { 10013, "SPORK_14_REQUIRE_SENTINEL_FLAG (retired)" },
  { 10014, "SPORK_15_DETERMINISTIC_MNS_ENABLED (retired)" },
  { 10015, "SPORK_16_INSTANTSEND_AUTOLOCKS (retired)" },
  { 10016, "SPORK_17_QUORUM_DKG_ENABLED" },
  { 10017, "SPORK_18_QUORUM_DEBUG_ENABLED (retired)" },
  { 10018, "SPORK_19_CHAINLOCKS_ENABLED" },
  { 10019, "SPORK_20_INSTANTSEND_LLMQ_BASED (retired)" },
  { 10020, "SPORK_21_QUORUM_ALL_CONNECTED" },
  { 10021, "SPORK_22_PS_MORE_PARTICIPANTS (retired)" },
  { 10022, "SPORK_23_QUORUM_POSE" },
  { 10023, "SPORK_24_TEST_EHF (retired)" },
  { (uint32_t)-1, "SPORK_INVALID" },
  { 0, NULL }
};

/* masternode/sync.h:16-20 */
static const value_string dash_ssc_items[] = {
  { 1,   "MASTERNODE_SYNC_BLOCKCHAIN" },
  { 4,   "MASTERNODE_SYNC_GOVERNANCE" },
  { 10,  "MASTERNODE_SYNC_GOVOBJ" },
  { 11,  "MASTERNODE_SYNC_GOVOBJ_VOTE" },
  { 999, "MASTERNODE_SYNC_FINISHED" },
  { 0, NULL }
};

/* coinjoin/coinjoin.h:65-91 PoolMessage; text from coinjoin.cpp:507-555 */
static const value_string dash_cj_pool_messages[] = {
  {  0, "ERR_ALREADY_HAVE (Already have that input)" },
  {  1, "ERR_DENOM (No matching denominations found for mixing)" },
  {  2, "ERR_ENTRIES_FULL (Entries are full)" },
  {  3, "ERR_EXISTING_TX (Not compatible with existing transactions)" },
  {  4, "ERR_FEES (Transaction fees are too high)" },
  {  5, "ERR_INVALID_COLLATERAL (Collateral not valid)" },
  {  6, "ERR_INVALID_INPUT (Input is not valid)" },
  {  7, "ERR_INVALID_SCRIPT (Invalid script detected)" },
  {  8, "ERR_INVALID_TX (Transaction not valid)" },
  {  9, "ERR_MAXIMUM (Entry exceeds maximum size)" },
  { 10, "ERR_MN_LIST (Not in the Masternode list)" },
  { 11, "ERR_MODE (Incompatible mode)" },
  { 12, "ERR_NON_STANDARD_PUBKEY (not used)" },
  { 13, "ERR_NOT_A_MN (not used)" },
  { 14, "ERR_QUEUE_FULL (Masternode queue is full)" },
  { 15, "ERR_RECENT (Last queue was created too recently)" },
  { 16, "ERR_SESSION (Session not complete)" },
  { 17, "ERR_MISSING_TX (Missing input transaction information)" },
  { 18, "ERR_VERSION (Incompatible version)" },
  { 19, "MSG_NOERR (No errors detected)" },
  { 20, "MSG_SUCCESS (Transaction created successfully)" },
  { 21, "MSG_ENTRIES_ADDED (Your entries added successfully)" },
  { 22, "ERR_SIZE_MISMATCH (Inputs vs outputs size mismatch)" },
  { 0, NULL }
};

/* coinjoin/coinjoin.h:95-103 */
static const value_string dash_cj_pool_states[] = {
  { 0, "POOL_STATE_IDLE" },
  { 1, "POOL_STATE_QUEUE" },
  { 2, "POOL_STATE_ACCEPTING_ENTRIES" },
  { 3, "POOL_STATE_SIGNING" },
  { 4, "POOL_STATE_ERROR" },
  { 0, NULL }
};

/* coinjoin/coinjoin.h:107-111 */
static const value_string dash_cj_status_updates[] = {
  { 0, "STATUS_REJECTED" },
  { 1, "STATUS_ACCEPTED" },
  { 0, NULL }
};

/* governance/common.h:26-30 */
static const value_string dash_gov_object_types[] = {
  { 0, "Unknown" },
  { 1, "Proposal" },
  { 2, "Trigger" },
  { 0, NULL }
};

/* governance/vote.h:22-28, strings vote.cpp:58-72 */
static const value_string dash_gov_vote_outcomes[] = {
  { 0, "none" },
  { 1, "yes" },
  { 2, "no" },
  { 3, "abstain" },
  { 4, "unknown" },
  { 0, NULL }
};

/* governance/vote.h:32-39, strings vote.cpp:74-88 */
static const value_string dash_gov_vote_signals[] = {
  { 0, "none" },
  { 1, "funding" },
  { 2, "valid" },
  { 3, "delete" },
  { 4, "endorsed" },
  { 5, "unknown" },
  { 0, NULL }
};

/* ------------------------------------------------------------------------
 * Local helpers
 * ------------------------------------------------------------------------ */

/*
 * CoinJoin nDenom: a bitmask with exactly one of the 5 lowest bits set,
 * 1 << index into vecStandardDenominations (coinjoin/common.h:61-106).
 * Returns a short string for the Info column.
 */
static const char *
dash_cj_add_denom(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int *offset)
{
  proto_item *ti, *ai;
  proto_tree *subtree;
  int32_t     denom = (int32_t)tvb_get_letohl(tvb, *offset);
  const char *str;

  ti = proto_tree_add_item(tree, hf, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
  if (denom == 0) {
    str = "N/A";
  } else if (denom < 0 || denom >= (1 << array_length(dash_cj_denominations))) {
    str = "out-of-bounds";
    expert_add_info(pinfo, ti, &ei_dash_coinjoin_denom_invalid);
  } else if ((denom & (denom - 1)) != 0) {
    str = "non-denom";
    expert_add_info(pinfo, ti, &ei_dash_coinjoin_denom_invalid);
  } else {
    char    buf[ITEM_LABEL_LENGTH];
    int64_t amount = 0;
    unsigned i;

    for (i = 0; i < array_length(dash_cj_denominations); i++) {
      if (denom == (1 << i))
        amount = dash_cj_denominations[i];
    }
    subtree = proto_item_add_subtree(ti, ett_dash_varbytes);
    ai = proto_tree_add_int64(subtree, hf_dash_coinjoin_denom_amount, tvb, *offset, 4, amount);
    proto_item_set_generated(ai);
    format_dash_amount(buf, (uint64_t)amount);
    str = wmem_strdup(pinfo->pool, buf);
  }
  proto_item_append_text(ti, " (%s)", str);
  *offset += 4;
  return str;
}

/* Collateral transaction wrapped in its own labelled subtree */
static int
dash_cj_add_collateral(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                       const dash_pinfo_t *dpi)
{
  proto_item *ti;
  proto_tree *subtree;

  subtree = dash_subtree(tree, hf_dash_coinjoin_collateral, ett_dash_coinjoin_collateral, tvb, offset, &ti);
  offset = dissect_dash_tx(subtree, tvb, pinfo, offset, -1, dpi);
  proto_item_set_end(ti, tvb, offset);
  return offset;
}

/* Bitcoin CompactSize encoder, for rebuilding hash preimages */
static unsigned
dash_put_compactsize(uint8_t *buf, uint64_t n)
{
  if (n < 0xfd) {
    buf[0] = (uint8_t)n;
    return 1;
  } else if (n <= 0xffff) {
    buf[0] = 0xfd;
    phtoleu16(buf + 1, (uint16_t)n);
    return 3;
  } else if (n <= 0xffffffff) {
    buf[0] = 0xfe;
    phtoleu32(buf + 1, (uint32_t)n);
    return 5;
  }
  buf[0] = 0xff;
  phtoleu64(buf + 1, n);
  return 9;
}

/* Add a generated hash (displayed reversed) from a digest */
static const char *
dash_add_digest(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int offset, int len,
                const uint8_t *buf, size_t buflen)
{
  uint8_t     first[DASH_HASH_LEN], digest[DASH_HASH_LEN], rev[DASH_HASH_LEN];
  proto_item *ti;
  int         i;

  gcry_md_hash_buffer(GCRY_MD_SHA256, first, buf, buflen);
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, first, DASH_HASH_LEN);
  for (i = 0; i < DASH_HASH_LEN; i++)
    rev[i] = digest[DASH_HASH_LEN - 1 - i];
  ti = proto_tree_add_bytes_with_length(tree, hf, tvb, offset, len, rev, DASH_HASH_LEN);
  proto_item_set_generated(ti);
  return bytes_to_str_maxlen(pinfo->pool, rev, DASH_HASH_LEN, 0);
}

/*
 * CompactSize-prefixed bytes with a read-side cap (LIMITED_VECTOR or an
 * explicit size check in Dash Core).  Returns false, after flagging the
 * length, if the declared length is above the cap (the peer would reject
 * the message), in which case the caller should stop dissecting.
 */
static bool
dash_add_limited_varbytes(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo, int *offset,
                          uint64_t max)
{
  int         lenlen;
  uint64_t    len = dash_get_compactsize(tvb, *offset, &lenlen);
  proto_item *ti;

  if (len <= max) {
    dash_add_varbytes(tree, hf, tvb, offset);
    return true;
  }
  ti = proto_tree_add_uint64(tree, hf_dash_varbytes_length, tvb, *offset, lenlen, len);
  expert_add_info_format(pinfo, ti, &ei_dash_vector_too_long,
                         "Length %" PRIu64 " exceeds the maximum of %" PRIu64, len, max);
  *offset += lenlen;
  return false;
}

/* True if the bytes are valid UTF-8 text without control characters
 * (other than tab/CR/LF) */
static bool
dash_is_printable_text(const uint8_t *data, int len)
{
  int i;

  if (len <= 0 || !g_utf8_validate((const char *)data, len, NULL))
    return false;
  for (i = 0; i < len; i++) {
    uint8_t c = data[i];
    if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f)
      return false;
  }
  return true;
}

/* ------------------------------------------------------------------------
 * Sporks, sync status, mnauth, flag messages
 * ------------------------------------------------------------------------ */

/* spork: CSporkMessage (spork.h:93-117) */
static int
dissect_dash_msg_spork(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  int32_t     id;
  int64_t     value;
  proto_item *ti;

  id = dash_add_int(tree, hf_dash_spork_id, tvb, &offset, 4);
  value = (int64_t)tvb_get_letoh64(tvb, offset);
  ti = dash_add_item(tree, hf_dash_spork_value, tvb, &offset, 8, ENC_LITTLE_ENDIAN);
  if (value == 4070908800LL)
    proto_item_append_text(ti, " (OFF, default)");
  /* IsSporkActive(): value (as seconds since epoch) < now (spork.cpp:163-169) */
  ti = proto_tree_add_boolean(tree, hf_dash_spork_active, tvb, offset - 8, 8,
                              value < (int64_t)pinfo->abs_ts.secs);
  proto_item_set_generated(ti);
  dash_add_item(tree, hf_dash_spork_time_signed, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  /* LIMITED_VECTOR(vchSig, CPubKey::COMPACT_SIGNATURE_SIZE = 65) (spork.h:113-114) */
  if (dash_add_limited_varbytes(tree, hf_dash_spork_sig, tvb, pinfo, &offset, 65)) {
    /* MSG_SPORK inventory hash = SHA256d(full serialization) (spork.cpp:264-267) */
    dash_add_computed_hash(tree, hf_dash_spork_hash, tvb, 0, offset);
  }

  col_append_fstr(pinfo->cinfo, COL_INFO, " (%s = %" PRId64 ")",
                  val_to_str(pinfo->pool, (uint32_t)id, dash_spork_ids, "Unknown spork %d"), value);
  return offset;
}

/* ssc: SYNCSTATUSCOUNT (net_governance.cpp:151,163; node/sync_manager.cpp:319-331) */
static int
dissect_dash_msg_ssc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int     offset = 0;
  int32_t item, count;

  item  = dash_add_int(tree, hf_dash_ssc_item, tvb, &offset, 4);
  count = dash_add_int(tree, hf_dash_ssc_count, tvb, &offset, 4);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%s: %d)",
                  val_to_str(pinfo->pool, (uint32_t)item, dash_ssc_items, "Unknown item %d"), count);
  return offset;
}

/* mnauth: CMNAuth (evo/mnauth.h:46-56) */
static int
dissect_dash_msg_mnauth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int offset = 0;

  col_append_fstr(pinfo->cinfo, COL_INFO, " (proTx %s)",
                  dash_rhash_str(pinfo->pool, tvb, offset, DASH_HASH_LEN));
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_mnauth_sig, tvb, &offset, DASH_BLS_SIG_LEN, ENC_NA);
  return offset;
}

/* senddsq: bool (net_processing.cpp:4503-4515) */
static int
dissect_dash_msg_senddsq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_senddsq_enabled, tvb, &offset, 1, ENC_NA);
  return offset;
}

/* qsendrecsigs: bool (net_processing.cpp:4518-4522) */
static int
dissect_dash_msg_qsendrecsigs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  dash_add_item(tree, hf_dash_qsendrecsigs_enabled, tvb, &offset, 1, ENC_NA);
  return offset;
}

/* ------------------------------------------------------------------------
 * CoinJoin
 * ------------------------------------------------------------------------ */

/* dsa: CCoinJoinAccept (coinjoin/coinjoin.h:137-178) */
static int
dissect_dash_msg_dsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  static int * const flags[] = {
    &hf_dash_dsa_flag_promotion,
    &hf_dash_dsa_flag_demotion,
    NULL
  };
  const dash_pinfo_t *dpi = (const dash_pinfo_t *)data;
  int         offset = 0;
  const char *denom;

  denom  = dash_cj_add_denom(tree, hf_dash_dsa_denom, tvb, pinfo, &offset);
  offset = dash_cj_add_collateral(tree, tvb, pinfo, offset, dpi);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (denom %s)", denom);

  /* nFlags is serialized only if the stream version (the common version,
   * net_processing.cpp:5943 / client.cpp:1673) >= COINJOIN_REBALANCE_VERSION
   * (coinjoin.h:160-166) */
  if (dpi && dpi->common_version >= DASH_COINJOIN_REBALANCE_VERSION) {
    proto_item *ti;
    uint8_t     f = tvb_get_uint8(tvb, offset);

    ti = proto_tree_add_bitmask(tree, tvb, offset, hf_dash_dsa_flags, ett_dash_dsa_flags,
                                flags, ENC_NA);
    if ((f & 0x03) == 0x03)
      expert_add_info(pinfo, ti, &ei_dash_dsa_flags_invalid);
    else if (f & 0x01)
      col_append_str(pinfo->cinfo, COL_INFO, " [promotion]");
    else if (f & 0x02)
      col_append_str(pinfo->cinfo, COL_INFO, " [demotion]");
    offset += 1;
  }
  return offset;
}

/* dsi: CCoinJoinEntry - wire order vin, collateral, vout (coinjoin.h:203-221).
 * CTxDSIn serializes exactly as CTxIn (coinjoin/common.h:20-36). */
static int
dissect_dash_msg_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  const dash_pinfo_t *dpi = (const dash_pinfo_t *)data;
  int      offset = 0;
  uint64_t nin, nout, i;

  nin = dash_add_compactsize(tree, hf_dash_dsi_in_count, tvb, &offset);
  for (i = 0; i < nin; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txin(tree, tvb, pinfo, offset, (unsigned)i, dpi);
  }
  offset = dash_cj_add_collateral(tree, tvb, pinfo, offset, dpi);
  nout = dash_add_compactsize(tree, hf_dash_dsi_out_count, tvb, &offset);
  for (i = 0; i < nout; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txout(tree, hf_dash_dsi_out, tvb, pinfo, offset, (int)i, dpi);
  }
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 " in, %" PRIu64 " out)", nin, nout);
  return offset;
}

/* dsf: int nSessionID + CTransaction (server.cpp:1314; client.cpp:110-113) */
static int
dissect_dash_msg_dsf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int     offset = 0;
  int32_t session;

  session = dash_add_int(tree, hf_dash_dsf_session_id, tvb, &offset, 4);
  offset = dissect_dash_tx(tree, tvb, pinfo, offset, -1, (const dash_pinfo_t *)data);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (session %d)", session);
  return offset;
}

/* dss: std::vector<CTxIn> with signatures (client.cpp:608-626; server.cpp:254-259) */
static int
dissect_dash_msg_dss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int      offset = 0;
  uint64_t count, i;

  count = dash_add_compactsize(tree, hf_dash_dss_in_count, tvb, &offset);
  for (i = 0; i < count; i++) {
    DASH_LOOP_CHECK(tvb, offset);
    offset = dissect_dash_txin(tree, tvb, pinfo, offset, (unsigned)i, (const dash_pinfo_t *)data);
  }
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%" PRIu64 " inputs)", count);
  return offset;
}

/* dsc: int nSessionID + PoolMessage (server.cpp:1377; client.cpp:125-127) */
static int
dissect_dash_msg_dsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int     offset = 0;
  int32_t session, msg;

  session = dash_add_int(tree, hf_dash_dsc_session_id, tvb, &offset, 4);
  msg     = dash_add_int(tree, hf_dash_dsc_message_id, tvb, &offset, 4);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (session %d, %s)", session,
                  val_to_str(pinfo->pool, (uint32_t)msg, dash_cj_pool_messages, "message %d"));
  return offset;
}

/* dssu: CCoinJoinStatusUpdate (coinjoin.h:113-135).  nEntriesCount is
 * not serialized (coinjoin.h:131-134). */
static int
dissect_dash_msg_dssu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int     offset = 0;
  int32_t session, state, status, msg;

  session = dash_add_int(tree, hf_dash_dssu_session_id, tvb, &offset, 4);
  state   = dash_add_int(tree, hf_dash_dssu_state, tvb, &offset, 4);
  status  = dash_add_int(tree, hf_dash_dssu_status, tvb, &offset, 4);
  msg     = dash_add_int(tree, hf_dash_dssu_message_id, tvb, &offset, 4);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (session %d, %s, %s, %s)", session,
                  val_to_str(pinfo->pool, (uint32_t)state, dash_cj_pool_states, "state %d"),
                  val_to_str(pinfo->pool, (uint32_t)status, dash_cj_status_updates, "status %d"),
                  val_to_str(pinfo->pool, (uint32_t)msg, dash_cj_pool_messages, "message %d"));
  return offset;
}

/* dsq: CCoinJoinQueue (coinjoin.h:245-294, serialization 270-276).
 * masternodeOutpoint is not on the wire. */
static int
dissect_dash_msg_dsq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  const char *denom;
  bool        ready;

  denom = dash_cj_add_denom(tree, hf_dash_dsq_denom, tvb, pinfo, &offset);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_item(tree, hf_dash_dsq_time, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  ready = tvb_get_uint8(tvb, offset) != 0;
  dash_add_item(tree, hf_dash_dsq_ready, tvb, &offset, 1, ENC_NA);
  dash_add_varbytes(tree, hf_dash_dsq_sig, tvb, &offset);
  /* MSG_DSQ inventory hash = SHA256d(full serialization incl. vchSig) (coinjoin.cpp:47) */
  dash_add_computed_hash(tree, hf_dash_dsq_hash, tvb, 0, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " (denom %s%s)", denom, ready ? ", ready" : "");
  return offset;
}

/* dstx: CCoinJoinBroadcastTx (coinjoin.h:298-362, serialization 324-332) */
static int
dissect_dash_msg_dstx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int offset = 0;

  offset = dissect_dash_tx(tree, tvb, pinfo, offset, -1, (const dash_pinfo_t *)data);
  dash_add_hash(tree, hf_dash_protx_hash, tvb, &offset);
  dash_add_varbytes(tree, hf_dash_dstx_sig, tvb, &offset);
  dash_add_item(tree, hf_dash_dstx_sig_time, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  return offset;
}

/* ------------------------------------------------------------------------
 * Governance
 * ------------------------------------------------------------------------ */

/* govsync: uint256 nProp + CBloomFilter (net_governance.cpp:86-169;
 * CBloomFilter common/bloom.h:50-78) */
static int
dissect_dash_msg_govsync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  proto_item *ti;
  proto_tree *subtree;
  bool        all;
  uint64_t    flen;
  int         lenlen;
  const char *prop;

  all  = tvb_memeql(tvb, offset, (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", DASH_HASH_LEN) == 0;
  prop = dash_rhash_str(pinfo->pool, tvb, offset, DASH_HASH_LEN);
  ti = dash_add_hash(tree, hf_dash_govsync_prop_hash, tvb, &offset);
  if (all)
    proto_item_append_text(ti, " (all objects)");

  flen = dash_get_compactsize(tvb, offset, &lenlen);
  subtree = dash_subtree(tree, hf_dash_govsync_filter, ett_dash_govsync_filter, tvb, offset, &ti);
  /* vData is capped at MAX_BLOOM_FILTER_SIZE = 36000 (common/bloom.h:20, 78) */
  if (!dash_add_limited_varbytes(subtree, hf_dash_filter_data, tvb, pinfo, &offset, 36000)) {
    proto_item_set_end(ti, tvb, offset);
    return offset;
  }
  {
    /* CBloomFilter::IsWithinSizeConstraints(), checked at net_governance.cpp:108 */
    proto_item *hi = dash_add_item(subtree, hf_dash_filter_hash_funcs, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
    if (tvb_get_letohl(tvb, offset - 4) > 50)
      expert_add_info(pinfo, hi, &ei_dash_govsync_hash_funcs);
  }
  dash_add_item(subtree, hf_dash_filter_tweak, tvb, &offset, 4, ENC_LITTLE_ENDIAN);
  dash_add_item(subtree, hf_dash_filter_flags, tvb, &offset, 1, ENC_NA);
  proto_item_set_end(ti, tvb, offset);
  if (flen == 0)
    proto_item_append_text(ti, " (empty)");

  /* net_governance.cpp:115-167 */
  if (all)
    col_append_str(pinfo->cinfo, COL_INFO, " (all objects)");
  else if (flen == 0)
    col_append_fstr(pinfo->cinfo, COL_INFO, " (object %s)", prop);
  else
    col_append_fstr(pinfo->cinfo, COL_INFO, " (votes for %s)", prop);
  return offset;
}

/* govobj: CGovernanceObject; on the network only Governance::Object m_obj
 * (governance/object.h:294-316, governance/common.h:73-87) */
static int
dissect_dash_msg_govobj(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  int         lenlen, dlen, data_off, op_off, sig_off, sig_lenlen, siglen;
  int32_t     type;
  uint64_t    len;
  proto_item *ti;

  dash_add_hash(tree, hf_dash_govobj_parent_hash, tvb, &offset);
  dash_add_int(tree, hf_dash_govobj_revision, tvb, &offset, 4);
  dash_add_item(tree, hf_dash_govobj_time, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  dash_add_hash(tree, hf_dash_govobj_collateral_hash, tvb, &offset);

  /* vchData: raw bytes, normally a JSON object (common.cpp:46-49) */
  len  = dash_get_compactsize(tvb, offset, &lenlen);
  dlen = dash_check_len(tvb, offset + lenlen, len);
  data_off = offset + lenlen;
  ti = dash_add_varbytes(tree, hf_dash_govobj_data, tvb, &offset);
  if (dlen > 0) {
    const uint8_t *raw = tvb_get_ptr(tvb, data_off, dlen);
    if (dash_is_printable_text(raw, dlen)) {
      proto_tree *subtree = proto_item_get_subtree(ti);
      proto_item *si;
      const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, data_off, dlen, ENC_UTF_8);
      bool        hex = (dlen % 2) == 0;
      int         i;

      for (i = 0; hex && i < dlen; i++)
        hex = g_ascii_isxdigit(raw[i]);
      si = proto_tree_add_string(subtree, hf_dash_govobj_data_text, tvb, data_off, dlen, text);
      proto_item_set_generated(si);
      /* Older tooling stored hex-encoded JSON in the data itself */
      if (hex) {
        uint8_t *dec = (uint8_t *)wmem_alloc(pinfo->pool, dlen / 2 + 1);
        for (i = 0; i < dlen / 2; i++)
          dec[i] = (uint8_t)((g_ascii_xdigit_value(raw[2 * i]) << 4) | g_ascii_xdigit_value(raw[2 * i + 1]));
        dec[dlen / 2] = '\0';
        if (dash_is_printable_text(dec, dlen / 2)) {
          si = proto_tree_add_string(subtree, hf_dash_govobj_data_text, tvb, data_off, dlen, (const char *)dec);
          proto_item_append_text(si, " (hex-decoded)");
          proto_item_set_generated(si);
        }
      }
    }
  }

  type = dash_add_int(tree, hf_dash_govobj_type, tvb, &offset, 4);
  op_off = offset;
  offset = dissect_dash_outpoint(tree, hf_dash_govobj_mn_outpoint, tvb, pinfo, offset);
  sig_off = offset;
  len = dash_get_compactsize(tvb, offset, &sig_lenlen);
  /* LIMITED_VECTOR(vchSig, MAX_SIGNATURE_SIZE = 96) (governance/common.h:36, 84) */
  if (!dash_add_limited_varbytes(tree, hf_dash_govobj_sig, tvb, pinfo, &offset, 96))
    return offset;
  siglen = (int)len;

  /*
   * Object hash (governance/common.cpp:23-38), "doesn't match serialization":
   * SHA256d(hashParent || revision || time || HexStr(vchData) as string ||
   *         masternodeOutpoint || uint8 0 || uint32 0xffffffff || vchSig)
   */
  {
    static const char hexd[] = "0123456789abcdef";
    size_t   cap = 32 + 4 + 8 + 9 + (size_t)dlen * 2 + 36 + 1 + 4 + 9 + (size_t)siglen;
    uint8_t *buf = (uint8_t *)wmem_alloc(pinfo->pool, cap);
    size_t   n = 0;
    int      i;

    tvb_memcpy(tvb, buf, 0, 32 + 4 + 8);
    n = 32 + 4 + 8;
    n += dash_put_compactsize(buf + n, (uint64_t)dlen * 2);
    for (i = 0; i < dlen; i++) {
      uint8_t b = tvb_get_uint8(tvb, data_off + i);
      buf[n++] = hexd[b >> 4];
      buf[n++] = hexd[b & 0x0f];
    }
    tvb_memcpy(tvb, buf + n, op_off, 36);
    n += 36;
    buf[n++] = 0;
    phtoleu32(buf + n, 0xffffffff);
    n += 4;
    tvb_memcpy(tvb, buf + n, sig_off, sig_lenlen + siglen);
    n += sig_lenlen + siglen;
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %s)",
                    val_to_str(pinfo->pool, (uint32_t)type, dash_gov_object_types, "type %d"),
                    dash_add_digest(tree, hf_dash_govobj_hash, tvb, pinfo, 0, offset, buf, n));
  }
  return offset;
}

/* govobjvote: CGovernanceVote (governance/vote.h:61-208, serialization 190-207).
 * Note the wire order: outcome before signal. */
static int
dissect_dash_msg_govobjvote(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  int32_t     outcome, signal;
  int         lenlen;
  uint64_t    siglen;
  proto_item *ti;

  offset = dissect_dash_outpoint(tree, hf_dash_govvote_mn_outpoint, tvb, pinfo, offset);
  dash_add_hash(tree, hf_dash_govvote_parent_hash, tvb, &offset);
  outcome = dash_add_int(tree, hf_dash_govvote_outcome, tvb, &offset, 4);
  signal  = dash_add_int(tree, hf_dash_govvote_signal, tvb, &offset, 4);
  dash_add_item(tree, hf_dash_govvote_time, tvb, &offset, 8, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  siglen = dash_get_compactsize(tvb, offset, &lenlen);
  if (siglen > DASH_BLS_SIG_LEN) {
    /* LIMITED_VECTOR(vchSig, BLS_SIG_SIZE) on network reads (vote.h:197) */
    dash_add_limited_varbytes(tree, hf_dash_govvote_sig, tvb, pinfo, &offset, DASH_BLS_SIG_LEN);
    return offset;
  }
  ti = dash_add_varbytes(tree, hf_dash_govvote_sig, tvb, &offset);
  /* vote.h:197-201: network reads require 65 (ECDSA) or 96 (BLS) bytes */
  if (siglen == 65)
    proto_item_append_text(ti, " (ECDSA, voting key)");
  else if (siglen == 96)
    proto_item_append_text(ti, " (BLS, operator key)");
  else
    expert_add_info(pinfo, ti, &ei_dash_govvote_sig_size);

  /* Vote hash (vote.cpp:145-156): SHA256d(outpoint || uint8 0 || uint32 0xffffffff ||
   * parentHash || signal || outcome || time) - signal before outcome */
  {
    uint8_t buf[36 + 1 + 4 + 32 + 4 + 4 + 8];

    tvb_memcpy(tvb, buf, 0, 36);
    buf[36] = 0;
    phtoleu32(buf + 37, 0xffffffff);
    tvb_memcpy(tvb, buf + 41, 36, 32);
    phtoleu32(buf + 73, (uint32_t)signal);
    phtoleu32(buf + 77, (uint32_t)outcome);
    tvb_memcpy(tvb, buf + 81, 76, 8);
    dash_add_digest(tree, hf_dash_govvote_hash, tvb, pinfo, 0, offset, buf, sizeof buf);
  }

  col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %s)",
                  val_to_str(pinfo->pool, (uint32_t)signal, dash_gov_vote_signals, "signal %d"),
                  val_to_str(pinfo->pool, (uint32_t)outcome, dash_gov_vote_outcomes, "outcome %d"));
  return offset;
}

/* ------------------------------------------------------------------------
 * Registration
 * ------------------------------------------------------------------------ */

static void
dash_register_coinjoin_gov(void)
{
  dash_add_command("spork",        dissect_dash_msg_spork);
  dash_add_command("getsporks",    dissect_dash_msg_empty);
  dash_add_command("ssc",          dissect_dash_msg_ssc);
  dash_add_command("mnauth",       dissect_dash_msg_mnauth);
  dash_add_command("senddsq",      dissect_dash_msg_senddsq);
  dash_add_command("qsendrecsigs", dissect_dash_msg_qsendrecsigs);
  dash_add_command("qwatch",       dissect_dash_msg_empty);

  dash_add_command("dsa",          dissect_dash_msg_dsa);
  dash_add_command("dsi",          dissect_dash_msg_dsi);
  dash_add_command("dsf",          dissect_dash_msg_dsf);
  dash_add_command("dss",          dissect_dash_msg_dss);
  dash_add_command("dsc",          dissect_dash_msg_dsc);
  dash_add_command("dssu",         dissect_dash_msg_dssu);
  dash_add_command("dsq",          dissect_dash_msg_dsq);
  dash_add_command("dstx",         dissect_dash_msg_dstx);

  dash_add_command("govsync",      dissect_dash_msg_govsync);
  dash_add_command("govobj",       dissect_dash_msg_govobj);
  dash_add_command("govobjvote",   dissect_dash_msg_govobjvote);
}

void
proto_register_dash(void)
{
  static hf_register_info hf[] = {
    { &hf_dash_magic,
      { "Packet magic", "dash.magic",
        FT_UINT32, BASE_HEX, VALS(dash_magic_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_command,
      { "Command name", "dash.command",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_length,
      { "Payload length", "dash.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_checksum,
      { "Payload checksum", "dash.checksum",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "First 4 bytes of SHA256d(payload)", HFILL }
    },
    { &hf_dash_checksum_status,
      { "Checksum status", "dash.checksum.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_payload,
      { "Payload", "dash.payload",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_payload_data,
      { "Payload data", "dash.payload.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_varbytes_length,
      { "Length", "dash.length_prefix",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "CompactSize length prefix", HFILL }
    },
    { &hf_dash_address,
      { "Address", "dash.address",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Base58Check address", HFILL }
    },
    { &hf_dash_script_type,
      { "Script type", "dash.script.type",
        FT_UINT8, BASE_DEC, VALS(dash_script_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_outpoint_hash,
      { "Hash", "dash.outpoint.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_outpoint_index,
      { "Index", "dash.outpoint.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_bitset_size,
      { "Number of bits", "dash.bitset.size",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_bitset_count,
      { "Bits set", "dash.bitset.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_bitset_members,
      { "Set bits", "dash.bitset.members",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_ipv6,
      { "IPv6 address", "dash.service.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_ipv4,
      { "IPv4 address", "dash.service.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_port,
      { "Port", "dash.service.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_network,
      { "Network", "dash.service.network",
        FT_UINT8, BASE_DEC, VALS(dash_network_ids), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_addr_len,
      { "Address length", "dash.service.addr_len",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_service_addr_other,
      { "Address", "dash.service.addr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_service,
      { "Service", "dash.service",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo,
      { "Network info", "dash.netinfo",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_version,
      { "Version", "dash.netinfo.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_purpose_count,
      { "Purpose count", "dash.netinfo.purpose_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_purpose_entry,
      { "Purpose", "dash.netinfo.purpose_entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_purpose,
      { "Purpose", "dash.netinfo.purpose",
        FT_UINT8, BASE_DEC, VALS(dash_netinfo_purposes), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_entry_count,
      { "Entry count", "dash.netinfo.entry_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_entry,
      { "Entry", "dash.netinfo.entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_entry_type,
      { "Entry type", "dash.netinfo.entry_type",
        FT_UINT8, BASE_HEX, VALS(dash_netinfo_entry_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_domain,
      { "Domain", "dash.netinfo.domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_netinfo_domain_port,
      { "Port", "dash.netinfo.domain_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx,
      { "Transaction", "dash.tx",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_version,
      { "Version", "dash.tx.version",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_type,
      { "Type", "dash.tx.type",
        FT_UINT16, BASE_DEC, VALS(dash_tx_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_in_count,
      { "Input count", "dash.tx.in_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_in,
      { "Input", "dash.tx.in",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_in_prevout,
      { "Previous output", "dash.tx.in.prevout",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_in_script,
      { "Signature script", "dash.tx.in.script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_in_sequence,
      { "Sequence", "dash.tx.in.sequence",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_out_count,
      { "Output count", "dash.tx.out_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_out,
      { "Output", "dash.tx.out",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_out_value,
      { "Value", "dash.tx.out.value",
        FT_INT64, BASE_CUSTOM, CF_FUNC(format_dash_amount), 0x0,
        "Amount in duffs (1 DASH = 100000000 duffs)", HFILL }
    },
    { &hf_dash_tx_out_script,
      { "Public key script", "dash.tx.out.script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_lock_time,
      { "Lock time", "dash.tx.lock_time",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_payload,
      { "Extra payload", "dash.tx.payload",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_payload_size,
      { "Payload size", "dash.tx.payload.size",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_payload_data,
      { "Payload data", "dash.tx.payload.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_tx_txid,
      { "TXID", "dash.tx.txid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Transaction ID (computed)", HFILL }
    },
    { &hf_dash_tx_instance_hash,
      { "Instance hash", "dash.tx.instance_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SHA256d of the full serialization (computed)", HFILL }
    },
    { &hf_dash_block_header,
      { "Block header", "dash.block.header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_version,
      { "Version", "dash.block.version",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_prev,
      { "Previous block hash", "dash.block.prev",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_merkle_root,
      { "Merkle root", "dash.block.merkle_root",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_time,
      { "Time", "dash.block.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_bits,
      { "Bits", "dash.block.bits",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_nonce,
      { "Nonce", "dash.block.nonce",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_block_tx_count,
      { "Transaction count", "dash.block.tx_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_commitment,
      { "Final commitment", "dash.qc",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_version,
      { "Version", "dash.qc.version",
        FT_UINT16, BASE_DEC, VALS(dash_qc_versions), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_llmq_type,
      { "LLMQ type", "dash.llmq_type",
        FT_UINT8, BASE_DEC, VALS(dash_llmq_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_quorum_hash,
      { "Quorum hash", "dash.quorum_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_quorum_index,
      { "Quorum index", "dash.quorum_index",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_signers,
      { "Signers", "dash.qc.signers",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_valid_members,
      { "Valid members", "dash.qc.valid_members",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_quorum_pubkey,
      { "Quorum public key", "dash.qc.quorum_pubkey",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_vvec_hash,
      { "Verification vector hash", "dash.qc.vvec_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_quorum_sig,
      { "Quorum signature", "dash.qc.quorum_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qc_members_sig,
      { "Members signature", "dash.qc.members_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_version,
      { "Version", "dash.protx.version",
        FT_UINT16, BASE_DEC, VALS(dash_protx_versions), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_mn_type,
      { "Masternode type", "dash.protx.mn_type",
        FT_UINT16, BASE_DEC, VALS(dash_mn_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_mode,
      { "Mode", "dash.protx.mode",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_collateral,
      { "Collateral outpoint", "dash.protx.collateral",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_hash,
      { "ProTx hash", "dash.protx.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_owner_keyid,
      { "Owner key ID", "dash.protx.owner_keyid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_operator_pubkey,
      { "Operator public key", "dash.protx.operator_pubkey",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_voting_keyid,
      { "Voting key ID", "dash.protx.voting_keyid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_operator_reward,
      { "Operator reward", "dash.protx.operator_reward",
        FT_UINT16, BASE_CUSTOM, CF_FUNC(format_dash_basis_points), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_payout_script,
      { "Payout script", "dash.protx.payout_script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_operator_payout_script,
      { "Operator payout script", "dash.protx.operator_payout_script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_payout_count,
      { "Payout count", "dash.protx.payout_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_payout,
      { "Payout", "dash.protx.payout",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_payout_reward,
      { "Reward share", "dash.protx.payout.reward",
        FT_UINT16, BASE_CUSTOM, CF_FUNC(format_dash_basis_points), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share_count,
      { "Collateral share count", "dash.protx.share_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share,
      { "Collateral share", "dash.protx.share",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share_amount,
      { "Amount", "dash.protx.share.amount",
        FT_INT64, BASE_CUSTOM, CF_FUNC(format_dash_amount), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share_refund_script,
      { "Refund script", "dash.protx.share.refund_script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share_reward_script,
      { "Reward script", "dash.protx.share.reward_script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_share_index,
      { "Share index", "dash.protx.share_index",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_join_sig,
      { "Join signature", "dash.protx.join_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_early_period,
      { "Early period blocks", "dash.protx.early_period",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_early_penalty,
      { "Early penalty", "dash.protx.early_penalty",
        FT_INT64, BASE_CUSTOM, CF_FUNC(format_dash_amount), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_inputs_hash,
      { "Inputs hash", "dash.protx.inputs_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_platform_node_id,
      { "Platform node ID", "dash.protx.platform_node_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_platform_p2p_port,
      { "Platform P2P port", "dash.protx.platform_p2p_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_platform_http_port,
      { "Platform HTTP port", "dash.protx.platform_http_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_sig,
      { "Signature", "dash.protx.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_bls_sig,
      { "BLS signature", "dash.protx.bls_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_revoke_reason,
      { "Revocation reason", "dash.protx.revoke_reason",
        FT_UINT16, BASE_DEC, VALS(dash_revoke_reasons), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_actor_index,
      { "Actor index", "dash.protx.actor_index",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_sig_count,
      { "Signature count", "dash.protx.sig_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_protx_compact_sig,
      { "Compact signature", "dash.protx.compact_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_version,
      { "Version", "dash.cbtx.version",
        FT_UINT16, BASE_DEC, VALS(dash_cbtx_versions), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_height,
      { "Height", "dash.cbtx.height",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_merkle_mnlist,
      { "Masternode list merkle root", "dash.cbtx.merkle_mnlist",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_merkle_quorums,
      { "Quorums merkle root", "dash.cbtx.merkle_quorums",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_best_cl_height_diff,
      { "Best ChainLock height difference", "dash.cbtx.best_cl_height_diff",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_best_cl_sig,
      { "Best ChainLock signature", "dash.cbtx.best_cl_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_credit_pool,
      { "Credit pool balance", "dash.cbtx.credit_pool",
        FT_INT64, BASE_CUSTOM, CF_FUNC(format_dash_amount), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cbtx_merkle_asset_unlocks,
      { "Asset unlocks merkle root", "dash.cbtx.merkle_asset_unlocks",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qctx_version,
      { "Version", "dash.qctx.version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qctx_height,
      { "Height", "dash.qctx.height",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_mnhf_version,
      { "Version", "dash.mnhf.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_mnhf_version_bit,
      { "Version bit", "dash.mnhf.version_bit",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_mnhf_sig,
      { "Signature", "dash.mnhf.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_asset_version,
      { "Version", "dash.asset.version",
        FT_UINT8, BASE_DEC, VALS(dash_asset_versions), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_assetlock_output_count,
      { "Credit output count", "dash.assetlock.output_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_assetlock_output,
      { "Credit output", "dash.assetlock.output",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_assetunlock_index,
      { "Index", "dash.assetunlock.index",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_assetunlock_fee,
      { "Fee", "dash.assetunlock.fee",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Fee in duffs", HFILL }
    },
    { &hf_dash_assetunlock_requested_height,
      { "Requested height", "dash.assetunlock.requested_height",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_assetunlock_quorum_sig,
      { "Quorum signature", "dash.assetunlock.quorum_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_services,
      { "Services", "dash.services",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_services_network,
      { "NODE_NETWORK", "dash.services.network",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000001,
        NULL, HFILL }
    },
    { &hf_dash_services_bloom,
      { "NODE_BLOOM", "dash.services.bloom",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000004,
        NULL, HFILL }
    },
    { &hf_dash_services_compact_filters,
      { "NODE_COMPACT_FILTERS", "dash.services.compact_filters",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000040,
        NULL, HFILL }
    },
    { &hf_dash_services_network_limited,
      { "NODE_NETWORK_LIMITED", "dash.services.network_limited",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000400,
        NULL, HFILL }
    },
    { &hf_dash_services_headers_compressed,
      { "NODE_HEADERS_COMPRESSED", "dash.services.headers_compressed",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000800,
        NULL, HFILL }
    },
    { &hf_dash_services_p2p_v2,
      { "NODE_P2P_V2", "dash.services.p2p_v2",
        FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000001000,
        NULL, HFILL }
    },
    { &hf_dash_version_version,
      { "Protocol version", "dash.version.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_timestamp,
      { "Node timestamp", "dash.version.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_addr_recv,
      { "Address of receiving node", "dash.version.addr_recv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_addr_from,
      { "Address of sending node", "dash.version.addr_from",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_nonce,
      { "Random nonce", "dash.version.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_user_agent,
      { "User agent", "dash.version.user_agent",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_start_height,
      { "Block start height", "dash.version.start_height",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_relay,
      { "Relay transactions", "dash.version.relay",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_mnauth_challenge,
      { "MNAUTH challenge", "dash.version.mnauth_challenge",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_version_masternode,
      { "Masternode connection", "dash.version.masternode",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_addr_count,
      { "Count", "dash.addr.count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_addr_entry,
      { "Address", "dash.addr.entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_addr_timestamp,
      { "Timestamp", "dash.addr.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_inv_count,
      { "Count", "dash.inv.count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_inv_entry,
      { "Inventory vector", "dash.inv.entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_inv_type,
      { "Type", "dash.inv.type",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, VALS_EXT_PTR(&dash_inv_types_ext), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_inv_hash,
      { "Hash", "dash.inv.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_locator_version,
      { "Protocol version", "dash.locator.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_locator_count,
      { "Hash count", "dash.locator.count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_locator_hash,
      { "Block locator hash", "dash.locator.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_locator_stop,
      { "Hash stop", "dash.locator.stop",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_headers_count,
      { "Count", "dash.headers.count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_headers_entry,
      { "Header", "dash.headers.entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_headers_tx_count,
      { "Transaction count", "dash.headers.tx_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_flags,
      { "Compression flags", "dash.headers2.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_flag_version,
      { "Version", "dash.headers2.flags.version",
        FT_UINT8, BASE_DEC, VALS(dash_hdr2_version_offsets), 0x07,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_flag_prev,
      { "Previous block hash", "dash.headers2.flags.prev",
        FT_BOOLEAN, 8, TFS(&tfs_dash_present_compressed), 0x08,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_flag_time,
      { "Timestamp", "dash.headers2.flags.time",
        FT_BOOLEAN, 8, TFS(&tfs_dash_present_compressed), 0x10,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_flag_bits,
      { "Bits", "dash.headers2.flags.bits",
        FT_BOOLEAN, 8, TFS(&tfs_dash_present_compressed), 0x20,
        NULL, HFILL }
    },
    { &hf_dash_hdr2_time_offset,
      { "Time offset", "dash.headers2.time_offset",
        FT_INT16, BASE_DEC, NULL, 0x0,
        "Seconds since the previous header", HFILL }
    },
    { &hf_dash_ping_nonce,
      { "Nonce", "dash.ping.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_filter_data,
      { "Filter data", "dash.filter.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_filter_hash_funcs,
      { "Hash functions", "dash.filter.hash_funcs",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_filter_tweak,
      { "Tweak", "dash.filter.tweak",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_filter_flags,
      { "Flags", "dash.filter.flags",
        FT_UINT8, BASE_DEC, VALS(dash_bloom_flags), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_merkle_total_tx,
      { "Total transactions", "dash.merkleblock.total_tx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_merkle_hash_count,
      { "Hash count", "dash.merkleblock.hash_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_merkle_hash,
      { "Hash", "dash.merkleblock.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_merkle_flags,
      { "Flags", "dash.merkleblock.flags",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_announce,
      { "High-bandwidth announce", "dash.cmpct.announce",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_version,
      { "Version", "dash.cmpct.version",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_nonce,
      { "Nonce", "dash.cmpct.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_shortid_count,
      { "Short ID count", "dash.cmpct.shortid_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_shortid,
      { "Short ID", "dash.cmpct.shortid",
        FT_UINT48, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_prefilled_count,
      { "Prefilled transaction count", "dash.cmpct.prefilled_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_prefilled,
      { "Prefilled transaction", "dash.cmpct.prefilled",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_index_diff,
      { "Index (differential)", "dash.cmpct.index_diff",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_index,
      { "Index", "dash.cmpct.index",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_index_count,
      { "Index count", "dash.cmpct.index_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cmpct_block_hash,
      { "Block hash", "dash.cmpct.block_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_filter_type,
      { "Filter type", "dash.cf.filter_type",
        FT_UINT8, BASE_DEC, VALS(dash_filter_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_start_height,
      { "Start height", "dash.cf.start_height",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_stop_hash,
      { "Stop hash", "dash.cf.stop_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_block_hash,
      { "Block hash", "dash.cf.block_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_filter,
      { "Filter", "dash.cf.filter",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_prev_header,
      { "Previous filter header", "dash.cf.prev_header",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_count,
      { "Count", "dash.cf.count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_filter_hash,
      { "Filter hash", "dash.cf.filter_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_cf_header,
      { "Filter header", "dash.cf.header",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_txrcncl_version,
      { "Version", "dash.txrcncl.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_txrcncl_salt,
      { "Salt", "dash.txrcncl.salt",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_spork_id,
      { "Spork ID", "dash.spork.id",
        FT_INT32, BASE_DEC, VALS(dash_spork_ids), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_spork_value,
      { "Value", "dash.spork.value",
        FT_INT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_spork_active,
      { "Active at capture time", "dash.spork.active",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Spork value is lower than the frame time (CSporkManager::IsSporkActive)", HFILL }
    },
    { &hf_dash_spork_time_signed,
      { "Time signed", "dash.spork.time_signed",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_spork_sig,
      { "Signature", "dash.spork.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Compact ECDSA signature by the spork key", HFILL }
    },
    { &hf_dash_spork_hash,
      { "Spork hash", "dash.spork.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SHA256d of the message (MSG_SPORK inventory hash, computed)", HFILL }
    },
    { &hf_dash_ssc_item,
      { "Item ID", "dash.ssc.item",
        FT_INT32, BASE_DEC, VALS(dash_ssc_items), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_ssc_count,
      { "Count", "dash.ssc.count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_mnauth_sig,
      { "Signature", "dash.mnauth.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "BLS signature by the masternode operator key", HFILL }
    },
    { &hf_dash_senddsq_enabled,
      { "Send DSQ", "dash.senddsq.enabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_qsendrecsigs_enabled,
      { "Send recovered signatures", "dash.qsendrecsigs.enabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_coinjoin_denom_amount,
      { "Denomination amount", "dash.coinjoin.denom_amount",
        FT_INT64, BASE_CUSTOM, CF_FUNC(format_dash_amount), 0x0,
        "Amount for the denomination bit (computed)", HFILL }
    },
    { &hf_dash_coinjoin_collateral,
      { "Collateral transaction", "dash.coinjoin.collateral",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsa_denom,
      { "Denomination", "dash.dsa.denom",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsa_flags,
      { "Flags", "dash.dsa.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsa_flag_promotion,
      { "Promotion", "dash.dsa.flags.promotion",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
        NULL, HFILL }
    },
    { &hf_dash_dsa_flag_demotion,
      { "Demotion", "dash.dsa.flags.demotion",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
        NULL, HFILL }
    },
    { &hf_dash_dsi_in_count,
      { "Input count", "dash.dsi.in_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsi_out_count,
      { "Output count", "dash.dsi.out_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsi_out,
      { "Output", "dash.dsi.out",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsf_session_id,
      { "Session ID", "dash.dsf.session_id",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dss_in_count,
      { "Input count", "dash.dss.in_count",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsc_session_id,
      { "Session ID", "dash.dsc.session_id",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsc_message_id,
      { "Message", "dash.dsc.message_id",
        FT_INT32, BASE_DEC, VALS(dash_cj_pool_messages), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dssu_session_id,
      { "Session ID", "dash.dssu.session_id",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dssu_state,
      { "Pool state", "dash.dssu.state",
        FT_INT32, BASE_DEC, VALS(dash_cj_pool_states), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dssu_status,
      { "Status update", "dash.dssu.status",
        FT_INT32, BASE_DEC, VALS(dash_cj_status_updates), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dssu_message_id,
      { "Message", "dash.dssu.message_id",
        FT_INT32, BASE_DEC, VALS(dash_cj_pool_messages), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsq_denom,
      { "Denomination", "dash.dsq.denom",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsq_time,
      { "Time", "dash.dsq.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsq_ready,
      { "Ready", "dash.dsq.ready",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_dsq_sig,
      { "Signature", "dash.dsq.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "BLS signature by the masternode operator key", HFILL }
    },
    { &hf_dash_dsq_hash,
      { "Queue hash", "dash.dsq.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SHA256d of the message (MSG_DSQ inventory hash, computed)", HFILL }
    },
    { &hf_dash_dstx_sig,
      { "Signature", "dash.dstx.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "BLS signature by the masternode operator key", HFILL }
    },
    { &hf_dash_dstx_sig_time,
      { "Signature time", "dash.dstx.sig_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govsync_prop_hash,
      { "Object hash", "dash.govsync.prop_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Governance object hash (all zero = sync all objects)", HFILL }
    },
    { &hf_dash_govsync_filter,
      { "Bloom filter", "dash.govsync.filter",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_parent_hash,
      { "Parent hash", "dash.govobj.parent_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_revision,
      { "Revision", "dash.govobj.revision",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_time,
      { "Time", "dash.govobj.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_collateral_hash,
      { "Collateral hash", "dash.govobj.collateral_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Fee transaction ID", HFILL }
    },
    { &hf_dash_govobj_data,
      { "Data", "dash.govobj.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_data_text,
      { "Data (text)", "dash.govobj.data_text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Object data decoded as text (normally JSON)", HFILL }
    },
    { &hf_dash_govobj_type,
      { "Object type", "dash.govobj.type",
        FT_INT32, BASE_DEC, VALS(dash_gov_object_types), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_mn_outpoint,
      { "Masternode outpoint", "dash.govobj.mn_outpoint",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_sig,
      { "Signature", "dash.govobj.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govobj_hash,
      { "Object hash", "dash.govobj.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Governance object hash (MSG_GOVERNANCE_OBJECT inventory hash, computed)", HFILL }
    },
    { &hf_dash_govvote_mn_outpoint,
      { "Masternode outpoint", "dash.govobjvote.mn_outpoint",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govvote_parent_hash,
      { "Parent hash", "dash.govobjvote.parent_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Hash of the governance object voted on", HFILL }
    },
    { &hf_dash_govvote_outcome,
      { "Vote outcome", "dash.govobjvote.outcome",
        FT_INT32, BASE_DEC, VALS(dash_gov_vote_outcomes), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govvote_signal,
      { "Vote signal", "dash.govobjvote.signal",
        FT_INT32, BASE_DEC, VALS(dash_gov_vote_signals), 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govvote_time,
      { "Time", "dash.govobjvote.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dash_govvote_sig,
      { "Signature", "dash.govobjvote.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "65-byte compact ECDSA (voting key) or 96-byte BLS (operator key)", HFILL }
    },
    { &hf_dash_govvote_hash,
      { "Vote hash", "dash.govobjvote.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Vote hash (MSG_GOVERNANCE_OBJECT_VOTE inventory hash, computed)", HFILL }
    },/* END GENERATED HF_REG */
  };

  static int *ett[] = {
    &ett_dash,
    &ett_dash_payload,
    &ett_dash_varbytes,
    &ett_dash_keyid,
    &ett_dash_outpoint,
    &ett_dash_tx,
    &ett_dash_tx_in,
    &ett_dash_tx_out,
    &ett_dash_tx_payload,
    &ett_dash_bitset,
    &ett_dash_service,
    &ett_dash_netinfo,
    &ett_dash_netinfo_purpose,
    &ett_dash_netinfo_entry,
    &ett_dash_block_header,
    &ett_dash_commitment,
    &ett_dash_protx_payout,
    &ett_dash_protx_share,
    &ett_dash_services,
    &ett_dash_netaddr,
    &ett_dash_addr_entry,
    &ett_dash_inv_entry,
    &ett_dash_headers_entry,
    &ett_dash_hdr2_flags,
    &ett_dash_cmpct_prefilled,
    &ett_dash_dsa_flags,
    &ett_dash_coinjoin_collateral,
    &ett_dash_govsync_filter,
    &ett_dash_govobj_data,/* END GENERATED ETT_REG */
  };

  static ei_register_info ei[] = {
    { &ei_dash_command_unknown, { "dash.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL } },
    { &ei_dash_checksum_bad, { "dash.checksum.bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL } },
    { &ei_dash_trailing_data, { "dash.trailing_data", PI_MALFORMED, PI_WARN, "Unexpected data after the end of the message", EXPFILL } },
    { &ei_dash_payload_trailing, { "dash.tx.payload.trailing", PI_MALFORMED, PI_WARN, "Unexpected data after the end of the special transaction payload", EXPFILL } },
    { &ei_dash_address_length, { "dash.service.addr_len.invalid", PI_MALFORMED, PI_WARN, "Address length does not match network type", EXPFILL } },
    { &ei_dash_hdr2_version, { "dash.headers2.version.unknown", PI_PROTOCOL, PI_WARN, "Version offset refers to an unknown version", EXPFILL } },
    { &ei_dash_coinjoin_denom_invalid, { "dash.coinjoin.denom.invalid", PI_PROTOCOL, PI_WARN, "Not a valid CoinJoin denomination (exactly one of the 5 lowest bits must be set)", EXPFILL } },
    { &ei_dash_dsa_flags_invalid, { "dash.dsa.flags.invalid", PI_PROTOCOL, PI_WARN, "Promotion and demotion flags are both set", EXPFILL } },
    { &ei_dash_govvote_sig_size, { "dash.govobjvote.sig.bad_size", PI_MALFORMED, PI_WARN, "Vote signature must be 65 or 96 bytes", EXPFILL } },
    { &ei_dash_vector_too_long, { "dash.vector_too_long", PI_MALFORMED, PI_ERROR, "Vector length exceeds the limit enforced by Dash Core", EXPFILL } },
    { &ei_dash_govsync_hash_funcs, { "dash.govsync.filter.hash_funcs.too_many", PI_PROTOCOL, PI_WARN, "Number of hash functions exceeds MAX_HASH_FUNCS (50); the filter is rejected", EXPFILL } },/* END GENERATED EI_REG */
  };

  module_t        *dash_module;
  expert_module_t *expert_dash;

  proto_dash = proto_register_protocol("Dash P2P Protocol", "Dash", "dash");

  proto_register_field_array(proto_dash, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dash = expert_register_protocol(proto_dash);
  expert_register_field_array(expert_dash, ei, array_length(ei));

  dash_command_table = register_dissector_table("dash.command", "Dash Command", proto_dash,
                                                FT_STRING, STRING_CASE_SENSITIVE);

  dash_handle = register_dissector("dash", dissect_dash, proto_dash);

  dash_module = prefs_register_protocol(proto_dash, NULL);
  prefs_register_bool_preference(dash_module, "desegment",
                                 "Desegment all Dash messages spanning multiple TCP segments",
                                 "Whether the Dash dissector should desegment all messages"
                                 " spanning multiple TCP segments",
                                 &dash_desegment);
  prefs_register_bool_preference(dash_module, "verify_checksum",
                                 "Verify message checksums",
                                 "Whether to verify the double-SHA256 checksum in the message header",
                                 &dash_verify_checksum);
  prefs_register_uint_preference(dash_module, "default_version",
                                 "Default protocol version",
                                 "Protocol version assumed for a connection whose version messages"
                                 " were not captured. Some messages (e.g. mnlistdiff) are encoded"
                                 " differently depending on the negotiated version.",
                                 10, &dash_default_version);
}

void
proto_reg_handoff_dash(void)
{
  dissector_add_uint_range_with_preference("tcp.port", DASH_PORT_RANGE, dash_handle);
  heur_dissector_add("tcp", dissect_dash_heur, "Dash over TCP", "dash_tcp", proto_dash, HEURISTIC_ENABLE);

  dash_add_command("version",      dissect_dash_msg_version);
  dash_add_command("addr",         dissect_dash_msg_addr);
  dash_add_command("addrv2",       dissect_dash_msg_addrv2);
  dash_add_command("inv",          dissect_dash_msg_inv);
  dash_add_command("getdata",      dissect_dash_msg_inv);
  dash_add_command("notfound",     dissect_dash_msg_inv);
  dash_add_command("getblocks",    dissect_dash_msg_getheaders);
  dash_add_command("getheaders",   dissect_dash_msg_getheaders);
  dash_add_command("getheaders2",  dissect_dash_msg_getheaders);
  dash_add_command("headers",      dissect_dash_msg_headers);
  dash_add_command("headers2",     dissect_dash_msg_headers2);
  dash_add_command("tx",           dissect_dash_msg_tx);
  dash_add_command("block",        dissect_dash_msg_block);
  dash_add_command("ping",         dissect_dash_msg_ping);
  dash_add_command("pong",         dissect_dash_msg_ping);
  dash_add_command("filterload",   dissect_dash_msg_filterload);
  dash_add_command("filteradd",    dissect_dash_msg_filteradd);
  dash_add_command("merkleblock",  dissect_dash_msg_merkleblock);
  dash_add_command("sendcmpct",    dissect_dash_msg_sendcmpct);
  dash_add_command("cmpctblock",   dissect_dash_msg_cmpctblock);
  dash_add_command("getblocktxn",  dissect_dash_msg_getblocktxn);
  dash_add_command("blocktxn",     dissect_dash_msg_blocktxn);
  dash_add_command("getcfilters",  dissect_dash_msg_getcfilters);
  dash_add_command("getcfheaders", dissect_dash_msg_getcfilters);
  dash_add_command("cfilter",      dissect_dash_msg_cfilter);
  dash_add_command("cfheaders",    dissect_dash_msg_cfheaders);
  dash_add_command("getcfcheckpt", dissect_dash_msg_getcfcheckpt);
  dash_add_command("cfcheckpt",    dissect_dash_msg_cfcheckpt);
  dash_add_command("sendtxrcncl",  dissect_dash_msg_sendtxrcncl);

  /* messages without payload */
  dash_add_command("verack",       dissect_dash_msg_empty);
  dash_add_command("getaddr",      dissect_dash_msg_empty);
  dash_add_command("mempool",      dissect_dash_msg_empty);
  dash_add_command("filterclear",  dissect_dash_msg_empty);
  dash_add_command("sendaddrv2",   dissect_dash_msg_empty);
  dash_add_command("sendheaders",  dissect_dash_msg_empty);
  dash_add_command("sendheaders2", dissect_dash_msg_empty);

  dash_register_coinjoin_gov();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
