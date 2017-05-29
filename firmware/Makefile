APPVER = 1.0.0

NAME  = trezor

OBJS += usb.o
OBJS += u2f.o
OBJS += messages.o
OBJS += storage.o
OBJS += trezor.o
OBJS += pinmatrix.o
OBJS += fsm.o
OBJS += coins.o
OBJS += transaction.o
OBJS += protect.o
OBJS += layout2.o
OBJS += recovery.o
OBJS += reset.o
OBJS += signing.o
OBJS += crypto.o
OBJS += ethereum.o
OBJS += ethereum_tokens.o
OBJS += decred_pgpwordlist.o
OBJS += decred.o

OBJS += debug.o

OBJS += ../vendor/trezor-crypto/address.o
OBJS += ../vendor/trezor-crypto/bignum.o
OBJS += ../vendor/trezor-crypto/ecdsa.o
OBJS += ../vendor/trezor-crypto/curves.o
OBJS += ../vendor/trezor-crypto/secp256k1.o
OBJS += ../vendor/trezor-crypto/nist256p1.o
OBJS += ../vendor/trezor-crypto/ed25519-donna/ed25519.o
OBJS += ../vendor/trezor-crypto/hmac.o
OBJS += ../vendor/trezor-crypto/bip32.o
OBJS += ../vendor/trezor-crypto/bip39.o
OBJS += ../vendor/trezor-crypto/pbkdf2.o
OBJS += ../vendor/trezor-crypto/base58.o

OBJS += ../vendor/trezor-crypto/ripemd160.o
OBJS += ../vendor/trezor-crypto/sha2.o
OBJS += ../vendor/trezor-crypto/sha3.o
OBJS += ../vendor/trezor-crypto/blake256.o

OBJS += ../vendor/trezor-crypto/aes/aescrypt.o
OBJS += ../vendor/trezor-crypto/aes/aeskey.o
OBJS += ../vendor/trezor-crypto/aes/aestab.o
OBJS += ../vendor/trezor-crypto/aes/aes_modes.o

OBJS += ../vendor/trezor-qrenc/qr_encode.o

# OBJS += protob/pb_common.o
OBJS += protob/pb_decode.o
OBJS += protob/pb_encode.o
OBJS += protob/messages.pb.o
OBJS += protob/storage.pb.o
OBJS += protob/types.pb.o

include ../Makefile.include

CFLAGS += -Wno-sequence-point
CFLAGS += -Iprotob -DPB_FIELD_16BIT=1
CFLAGS += -DQR_MAX_VERSION=0
CFLAGS += -DDEBUG_LINK=0
CFLAGS += -DDEBUG_LOG=0
CFLAGS += -DSCM_REVISION='"$(shell git rev-parse HEAD | sed 's:\(..\):\\x\1:g')"'
CFLAGS += -DUSE_ETHEREUM=1
CFLAGS += -DUSE_DECRED=1

DECRED_TEST_OBJS = decred_pgpwordlist.o
DECRED_TEST_OBJS += decred.o
DECRED_TEST_OBJS += coins.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/address.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/base58.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/bignum.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/bip32.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/bip39.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/blake256.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/curves.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/ecdsa.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/ed25519-donna/ed25519.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/hmac.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/nist256p1.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/pbkdf2.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/ripemd160.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/secp256k1.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/sha2.o
DECRED_TEST_OBJS += ../vendor/trezor-crypto/sha3.o


decred_testbed: decred_testbed.o $(DECRED_TEST_OBJS)
	$(CC) -g -I../vendor/trezor-crypto decred_testbed.o $(DECRED_TEST_OBJS) -o decred_testbed

decred_tests: decred_tests.o $(DECRED_TEST_OBJS)
	$(CC) -g -I../vendor/trezor-crypto decred_tests.o  $(DECRED_TEST_OBJS) -lcheck -lsubunit -lrt -lpthread -lm   -o decred_tests
