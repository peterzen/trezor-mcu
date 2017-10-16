/* Automatically generated nanopb header */
/* Generated by nanopb-0.2.9.3 */

#ifndef _PB_TYPES_PB_H_
#define _PB_TYPES_PB_H_
#include "pb.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _FailureType {
    FailureType_Failure_UnexpectedMessage = 1,
    FailureType_Failure_ButtonExpected = 2,
    FailureType_Failure_SyntaxError = 3,
    FailureType_Failure_ActionCancelled = 4,
    FailureType_Failure_PinExpected = 5,
    FailureType_Failure_PinCancelled = 6,
    FailureType_Failure_PinInvalid = 7,
    FailureType_Failure_InvalidSignature = 8,
    FailureType_Failure_Other = 9,
    FailureType_Failure_NotEnoughFunds = 10,
    FailureType_Failure_NotInitialized = 11,
    FailureType_Failure_FirmwareError = 99
} FailureType;

typedef enum _OutputScriptType {
    OutputScriptType_PAYTOADDRESS = 0,
    OutputScriptType_PAYTOSCRIPTHASH = 1,
    OutputScriptType_PAYTOMULTISIG = 2,
    OutputScriptType_PAYTOOPRETURN = 3,
    OutputScriptType_PAYTOWITNESS = 4,
    OutputScriptType_PAYTOP2SHWITNESS = 5
} OutputScriptType;

typedef enum _InputScriptType {
    InputScriptType_SPENDADDRESS = 0,
    InputScriptType_SPENDMULTISIG = 1,
    InputScriptType_EXTERNAL = 2,
    InputScriptType_SPENDWITNESS = 3,
    InputScriptType_SPENDP2SHWITNESS = 4
} InputScriptType;

typedef enum _RequestType {
    RequestType_TXINPUT = 0,
    RequestType_TXOUTPUT = 1,
    RequestType_TXMETA = 2,
    RequestType_TXFINISHED = 3,
    RequestType_TXEXTRADATA = 4
} RequestType;

typedef enum _ButtonRequestType {
    ButtonRequestType_ButtonRequest_Other = 1,
    ButtonRequestType_ButtonRequest_FeeOverThreshold = 2,
    ButtonRequestType_ButtonRequest_ConfirmOutput = 3,
    ButtonRequestType_ButtonRequest_ResetDevice = 4,
    ButtonRequestType_ButtonRequest_ConfirmWord = 5,
    ButtonRequestType_ButtonRequest_WipeDevice = 6,
    ButtonRequestType_ButtonRequest_ProtectCall = 7,
    ButtonRequestType_ButtonRequest_SignTx = 8,
    ButtonRequestType_ButtonRequest_FirmwareCheck = 9,
    ButtonRequestType_ButtonRequest_Address = 10,
    ButtonRequestType_ButtonRequest_PublicKey = 11
} ButtonRequestType;

typedef enum _PinMatrixRequestType {
    PinMatrixRequestType_PinMatrixRequestType_Current = 1,
    PinMatrixRequestType_PinMatrixRequestType_NewFirst = 2,
    PinMatrixRequestType_PinMatrixRequestType_NewSecond = 3
} PinMatrixRequestType;

typedef enum _RecoveryDeviceType {
    RecoveryDeviceType_RecoveryDeviceType_ScrambledWords = 0,
    RecoveryDeviceType_RecoveryDeviceType_Matrix = 1
} RecoveryDeviceType;

typedef enum _WordRequestType {
    WordRequestType_WordRequestType_Plain = 0,
    WordRequestType_WordRequestType_Matrix9 = 1,
    WordRequestType_WordRequestType_Matrix6 = 2
} WordRequestType;

/* Struct definitions */
typedef struct _CoinType {
    bool has_coin_name;
    char coin_name[17];
    bool has_coin_shortcut;
    char coin_shortcut[10];
    bool has_address_type;
    uint32_t address_type;
    bool has_maxfee_kb;
    uint64_t maxfee_kb;
    bool has_address_type_p2sh;
    uint32_t address_type_p2sh;
    bool has_signed_message_header;
    char signed_message_header[32];
    bool has_xpub_magic;
    uint32_t xpub_magic;
    bool has_xprv_magic;
    uint32_t xprv_magic;
    bool has_segwit;
    bool segwit;
} CoinType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DecredOutPointType_hash_t;

typedef struct {
    size_t size;
    uint8_t bytes[1];
} DecredOutPointType_tree_t;

typedef struct _DecredOutPointType {
    DecredOutPointType_hash_t hash;
    uint64_t index;
    bool has_tree;
    DecredOutPointType_tree_t tree;
} DecredOutPointType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} HDNodeType_chain_code_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} HDNodeType_private_key_t;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} HDNodeType_public_key_t;

typedef struct _HDNodeType {
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    HDNodeType_chain_code_t chain_code;
    bool has_private_key;
    HDNodeType_private_key_t private_key;
    bool has_public_key;
    HDNodeType_public_key_t public_key;
} HDNodeType;

typedef struct _IdentityType {
    bool has_proto;
    char proto[9];
    bool has_user;
    char user[64];
    bool has_host;
    char host[64];
    bool has_port;
    char port[6];
    bool has_path;
    char path[256];
    bool has_index;
    uint32_t index;
} IdentityType;

typedef struct {
    size_t size;
    uint8_t bytes[520];
} TxOutputBinType_script_pubkey_t;

typedef struct _TxOutputBinType {
    uint64_t amount;
    TxOutputBinType_script_pubkey_t script_pubkey;
} TxOutputBinType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} TxRequestDetailsType_tx_hash_t;

typedef struct _TxRequestDetailsType {
    bool has_request_index;
    uint32_t request_index;
    bool has_tx_hash;
    TxRequestDetailsType_tx_hash_t tx_hash;
    bool has_extra_data_len;
    uint32_t extra_data_len;
    bool has_extra_data_offset;
    uint32_t extra_data_offset;
} TxRequestDetailsType;

typedef struct {
    size_t size;
    uint8_t bytes[73];
} TxRequestSerializedType_signature_t;

typedef struct {
    size_t size;
    uint8_t bytes[2048];
} TxRequestSerializedType_serialized_tx_t;

typedef struct _TxRequestSerializedType {
    bool has_signature_index;
    uint32_t signature_index;
    bool has_signature;
    TxRequestSerializedType_signature_t signature;
    bool has_serialized_tx;
    TxRequestSerializedType_serialized_tx_t serialized_tx;
} TxRequestSerializedType;

typedef struct _HDNodePathType {
    HDNodeType node;
    size_t address_n_count;
    uint32_t address_n[8];
} HDNodePathType;

typedef struct {
    size_t size;
    uint8_t bytes[73];
} MultisigRedeemScriptType_signatures_t;

typedef struct _MultisigRedeemScriptType {
    size_t pubkeys_count;
    HDNodePathType pubkeys[15];
    size_t signatures_count;
    MultisigRedeemScriptType_signatures_t signatures[15];
    bool has_m;
    uint32_t m;
} MultisigRedeemScriptType;

typedef struct {
    size_t size;
    uint8_t bytes[255];
} DecredTxInType_signature_script_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DecredTxInType_prev_hash_t;

typedef struct {
    size_t size;
    uint8_t bytes[1650];
} DecredTxInType_script_sig_t;

typedef struct _DecredTxInType {
    DecredOutPointType previous_out_point;
    uint32_t sequence;
    int64_t value_in;
    uint32_t block_height;
    uint32_t block_index;
    DecredTxInType_signature_script_t signature_script;
    DecredTxInType_prev_hash_t prev_hash;
    bool has_script_type;
    InputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_amount;
    uint64_t amount;
    size_t address_n_count;
    uint32_t address_n[8];
    uint32_t prev_index;
    bool has_script_sig;
    DecredTxInType_script_sig_t script_sig;
} DecredTxInType;

typedef struct {
    size_t size;
    uint8_t bytes[255];
} DecredTxOutType_pk_script_t;

typedef struct {
    size_t size;
    uint8_t bytes[80];
} DecredTxOutType_op_return_data_t;

typedef struct _DecredTxOutType {
    int64_t value;
    uint32_t version;
    DecredTxOutType_pk_script_t pk_script;
    bool has_address;
    char address[54];
    size_t address_n_count;
    uint32_t address_n[8];
    uint64_t amount;
    OutputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_op_return_data;
    DecredTxOutType_op_return_data_t op_return_data;
} DecredTxOutType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} TxInputType_prev_hash_t;

typedef struct {
    size_t size;
    uint8_t bytes[1650];
} TxInputType_script_sig_t;

typedef struct _TxInputType {
    size_t address_n_count;
    uint32_t address_n[8];
    TxInputType_prev_hash_t prev_hash;
    uint32_t prev_index;
    bool has_script_sig;
    TxInputType_script_sig_t script_sig;
    bool has_sequence;
    uint32_t sequence;
    bool has_script_type;
    InputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_amount;
    uint64_t amount;
} TxInputType;

typedef struct {
    size_t size;
    uint8_t bytes[80];
} TxOutputType_op_return_data_t;

typedef struct _TxOutputType {
    bool has_address;
    char address[54];
    size_t address_n_count;
    uint32_t address_n[8];
    uint64_t amount;
    OutputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_op_return_data;
    TxOutputType_op_return_data_t op_return_data;
} TxOutputType;

typedef struct {
    size_t size;
    uint8_t bytes[1024];
} DecredTransactionType_extra_data_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DecredTransactionType_cached_hash_t;

typedef struct _DecredTransactionType {
    bool has_version;
    int32_t version;
    size_t inputs_count;
    DecredTxInType inputs[1];
    size_t bin_outputs_count;
    TxOutputBinType bin_outputs[1];
    bool has_lock_time;
    uint32_t lock_time;
    size_t outputs_count;
    DecredTxOutType outputs[1];
    bool has_inputs_cnt;
    uint32_t inputs_cnt;
    bool has_outputs_cnt;
    uint32_t outputs_cnt;
    bool has_extra_data;
    DecredTransactionType_extra_data_t extra_data;
    bool has_extra_data_len;
    uint32_t extra_data_len;
    DecredTransactionType_cached_hash_t cached_hash;
    bool has_expiry;
    uint32_t expiry;
} DecredTransactionType;

typedef struct {
    size_t size;
    uint8_t bytes[1024];
} TransactionType_extra_data_t;

typedef struct _TransactionType {
    bool has_version;
    uint32_t version;
    size_t inputs_count;
    TxInputType inputs[1];
    size_t bin_outputs_count;
    TxOutputBinType bin_outputs[1];
    bool has_lock_time;
    uint32_t lock_time;
    size_t outputs_count;
    TxOutputType outputs[1];
    bool has_inputs_cnt;
    uint32_t inputs_cnt;
    bool has_outputs_cnt;
    uint32_t outputs_cnt;
    bool has_extra_data;
    TransactionType_extra_data_t extra_data;
    bool has_extra_data_len;
    uint32_t extra_data_len;
} TransactionType;

/* Extensions */
extern const pb_extension_type_t wire_in;
extern const pb_extension_type_t wire_out;
extern const pb_extension_type_t wire_debug_in;
extern const pb_extension_type_t wire_debug_out;

/* Default values for struct fields */
extern const uint32_t CoinType_address_type_default;
extern const uint32_t CoinType_address_type_p2sh_default;
extern const uint32_t CoinType_xpub_magic_default;
extern const uint32_t CoinType_xprv_magic_default;
extern const uint32_t TxInputType_sequence_default;
extern const InputScriptType TxInputType_script_type_default;
extern const uint32_t IdentityType_index_default;
extern const uint32_t DecredTxInType_sequence_default;
extern const InputScriptType DecredTxInType_script_type_default;

/* Initializer values for message structs */
#define HDNodeType_init_default                  {0, 0, 0, {0, {0}}, false, {0, {0}}, false, {0, {0}}}
#define HDNodePathType_init_default              {HDNodeType_init_default, 0, {0, 0, 0, 0, 0, 0, 0, 0}}
#define CoinType_init_default                    {false, "", false, "", false, 0u, false, 0, false, 5u, false, "", false, 76067358u, false, 76066276u, false, 0}
#define MultisigRedeemScriptType_init_default    {0, {HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default}, 0, {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}, false, 0}
#define TxInputType_init_default                 {0, {0, 0, 0, 0, 0, 0, 0, 0}, {0, {0}}, 0, false, {0, {0}}, false, 4294967295u, false, InputScriptType_SPENDADDRESS, false, MultisigRedeemScriptType_init_default, false, 0}
#define TxOutputType_init_default                {false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_default, false, {0, {0}}}
#define TxOutputBinType_init_default             {0, {0, {0}}}
#define TransactionType_init_default             {false, 0, 0, {TxInputType_init_default}, 0, {TxOutputBinType_init_default}, false, 0, 0, {TxOutputType_init_default}, false, 0, false, 0, false, {0, {0}}, false, 0}
#define TxRequestDetailsType_init_default        {false, 0, false, {0, {0}}, false, 0, false, 0}
#define TxRequestSerializedType_init_default     {false, 0, false, {0, {0}}, false, {0, {0}}}
#define IdentityType_init_default                {false, "", false, "", false, "", false, "", false, "", false, 0u}
#define DecredOutPointType_init_default          {{0, {0}}, 0, false, {0, {0}}}
#define DecredTxInType_init_default              {DecredOutPointType_init_default, 4294967295u, 0, 0, 0, {0, {0}}, {0, {0}}, false, InputScriptType_SPENDADDRESS, false, MultisigRedeemScriptType_init_default, false, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, false, {0, {0}}}
#define DecredTxOutType_init_default             {0, 0, {0, {0}}, false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_default, false, {0, {0}}}
#define DecredTransactionType_init_default       {false, 0, 0, {DecredTxInType_init_default}, 0, {TxOutputBinType_init_default}, false, 0, 0, {DecredTxOutType_init_default}, false, 0, false, 0, false, {0, {0}}, false, 0, {0, {0}}, false, 0}
#define HDNodeType_init_zero                     {0, 0, 0, {0, {0}}, false, {0, {0}}, false, {0, {0}}}
#define HDNodePathType_init_zero                 {HDNodeType_init_zero, 0, {0, 0, 0, 0, 0, 0, 0, 0}}
#define CoinType_init_zero                       {false, "", false, "", false, 0, false, 0, false, 0, false, "", false, 0, false, 0, false, 0}
#define MultisigRedeemScriptType_init_zero       {0, {HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero}, 0, {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}, false, 0}
#define TxInputType_init_zero                    {0, {0, 0, 0, 0, 0, 0, 0, 0}, {0, {0}}, 0, false, {0, {0}}, false, 0, false, (InputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, 0}
#define TxOutputType_init_zero                   {false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, {0, {0}}}
#define TxOutputBinType_init_zero                {0, {0, {0}}}
#define TransactionType_init_zero                {false, 0, 0, {TxInputType_init_zero}, 0, {TxOutputBinType_init_zero}, false, 0, 0, {TxOutputType_init_zero}, false, 0, false, 0, false, {0, {0}}, false, 0}
#define TxRequestDetailsType_init_zero           {false, 0, false, {0, {0}}, false, 0, false, 0}
#define TxRequestSerializedType_init_zero        {false, 0, false, {0, {0}}, false, {0, {0}}}
#define IdentityType_init_zero                   {false, "", false, "", false, "", false, "", false, "", false, 0}
#define DecredOutPointType_init_zero             {{0, {0}}, 0, false, {0, {0}}}
#define DecredTxInType_init_zero                 {DecredOutPointType_init_zero, 0, 0, 0, 0, {0, {0}}, {0, {0}}, false, (InputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, false, {0, {0}}}
#define DecredTxOutType_init_zero                {0, 0, {0, {0}}, false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, {0, {0}}}
#define DecredTransactionType_init_zero          {false, 0, 0, {DecredTxInType_init_zero}, 0, {TxOutputBinType_init_zero}, false, 0, 0, {DecredTxOutType_init_zero}, false, 0, false, 0, false, {0, {0}}, false, 0, {0, {0}}, false, 0}

/* Field tags (for use in manual encoding/decoding) */
#define CoinType_coin_name_tag                   1
#define CoinType_coin_shortcut_tag               2
#define CoinType_address_type_tag                3
#define CoinType_maxfee_kb_tag                   4
#define CoinType_address_type_p2sh_tag           5
#define CoinType_signed_message_header_tag       8
#define CoinType_xpub_magic_tag                  9
#define CoinType_xprv_magic_tag                  10
#define CoinType_segwit_tag                      11
#define DecredOutPointType_hash_tag              1
#define DecredOutPointType_index_tag             2
#define DecredOutPointType_tree_tag              3
#define HDNodeType_depth_tag                     1
#define HDNodeType_fingerprint_tag               2
#define HDNodeType_child_num_tag                 3
#define HDNodeType_chain_code_tag                4
#define HDNodeType_private_key_tag               5
#define HDNodeType_public_key_tag                6
#define IdentityType_proto_tag                   1
#define IdentityType_user_tag                    2
#define IdentityType_host_tag                    3
#define IdentityType_port_tag                    4
#define IdentityType_path_tag                    5
#define IdentityType_index_tag                   6
#define TxOutputBinType_amount_tag               1
#define TxOutputBinType_script_pubkey_tag        2
#define TxRequestDetailsType_request_index_tag   1
#define TxRequestDetailsType_tx_hash_tag         2
#define TxRequestDetailsType_extra_data_len_tag  3
#define TxRequestDetailsType_extra_data_offset_tag 4
#define TxRequestSerializedType_signature_index_tag 1
#define TxRequestSerializedType_signature_tag    2
#define TxRequestSerializedType_serialized_tx_tag 3
#define HDNodePathType_node_tag                  1
#define HDNodePathType_address_n_tag             2
#define MultisigRedeemScriptType_pubkeys_tag     1
#define MultisigRedeemScriptType_signatures_tag  2
#define MultisigRedeemScriptType_m_tag           3
#define DecredTxInType_previous_out_point_tag    1
#define DecredTxInType_sequence_tag              2
#define DecredTxInType_value_in_tag              3
#define DecredTxInType_block_height_tag          4
#define DecredTxInType_block_index_tag           5
#define DecredTxInType_signature_script_tag      6
#define DecredTxInType_prev_hash_tag             7
#define DecredTxInType_script_type_tag           8
#define DecredTxInType_multisig_tag              9
#define DecredTxInType_amount_tag                10
#define DecredTxInType_address_n_tag             11
#define DecredTxInType_prev_index_tag            12
#define DecredTxInType_script_sig_tag            13
#define DecredTxOutType_value_tag                1
#define DecredTxOutType_version_tag              2
#define DecredTxOutType_pk_script_tag            3
#define DecredTxOutType_address_tag              4
#define DecredTxOutType_address_n_tag            5
#define DecredTxOutType_amount_tag               6
#define DecredTxOutType_script_type_tag          7
#define DecredTxOutType_multisig_tag             8
#define DecredTxOutType_op_return_data_tag       9
#define TxInputType_address_n_tag                1
#define TxInputType_prev_hash_tag                2
#define TxInputType_prev_index_tag               3
#define TxInputType_script_sig_tag               4
#define TxInputType_sequence_tag                 5
#define TxInputType_script_type_tag              6
#define TxInputType_multisig_tag                 7
#define TxInputType_amount_tag                   8
#define TxOutputType_address_tag                 1
#define TxOutputType_address_n_tag               2
#define TxOutputType_amount_tag                  3
#define TxOutputType_script_type_tag             4
#define TxOutputType_multisig_tag                5
#define TxOutputType_op_return_data_tag          6
#define DecredTransactionType_version_tag        1
#define DecredTransactionType_inputs_tag         2
#define DecredTransactionType_bin_outputs_tag    3
#define DecredTransactionType_lock_time_tag      4
#define DecredTransactionType_outputs_tag        5
#define DecredTransactionType_inputs_cnt_tag     6
#define DecredTransactionType_outputs_cnt_tag    7
#define DecredTransactionType_extra_data_tag     8
#define DecredTransactionType_extra_data_len_tag 9
#define DecredTransactionType_cached_hash_tag    10
#define DecredTransactionType_expiry_tag         11
#define TransactionType_version_tag              1
#define TransactionType_inputs_tag               2
#define TransactionType_bin_outputs_tag          3
#define TransactionType_outputs_tag              5
#define TransactionType_lock_time_tag            4
#define TransactionType_inputs_cnt_tag           6
#define TransactionType_outputs_cnt_tag          7
#define TransactionType_extra_data_tag           8
#define TransactionType_extra_data_len_tag       9
#define wire_in_tag                              50002
#define wire_out_tag                             50003
#define wire_debug_in_tag                        50004
#define wire_debug_out_tag                       50005

/* Struct field encoding specification for nanopb */
extern const pb_field_t HDNodeType_fields[7];
extern const pb_field_t HDNodePathType_fields[3];
extern const pb_field_t CoinType_fields[10];
extern const pb_field_t MultisigRedeemScriptType_fields[4];
extern const pb_field_t TxInputType_fields[9];
extern const pb_field_t TxOutputType_fields[7];
extern const pb_field_t TxOutputBinType_fields[3];
extern const pb_field_t TransactionType_fields[10];
extern const pb_field_t TxRequestDetailsType_fields[5];
extern const pb_field_t TxRequestSerializedType_fields[4];
extern const pb_field_t IdentityType_fields[7];
extern const pb_field_t DecredOutPointType_fields[4];
extern const pb_field_t DecredTxInType_fields[14];
extern const pb_field_t DecredTxOutType_fields[10];
extern const pb_field_t DecredTransactionType_fields[12];

/* Maximum encoded size of messages (where known) */
#define HDNodeType_size                          121
#define HDNodePathType_size                      171
#define CoinType_size                            102
#define MultisigRedeemScriptType_size            3741
#define TxInputType_size                         5508
#define TxOutputType_size                        3947
#define TxOutputBinType_size                     534
#define TransactionType_size                     11055
#define TxRequestDetailsType_size                52
#define TxRequestSerializedType_size             2132
#define IdentityType_size                        416
#define DecredOutPointType_size                  48
#define DecredTxInType_size                      5839
#define DecredTxOutType_size                     4222
#define DecredTransactionType_size               11706

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
