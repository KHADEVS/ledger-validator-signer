# From LedgerHQ/app-btec (Apache-2.0). Modified 2026.

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

APPNAME      = "ETH Validator"
APPVERSION_M = 0
APPVERSION_N = 0
APPVERSION_P = 1
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

VARIANT_PARAM = COIN
VARIANT_VALUES = eth_validator

# Only the validator keys of EIP-2334 can be derived.
APP_LOAD_PARAMS += --path "12381/3600" --curve bls12381g1

ICONNAME = icons/app.gif

ENABLE_BLUETOOTH = 0
DEBUG ?= 0

DEFINES += HAVE_BLS

# make TEST_BUILD=1: adds the commands the test suite needs. Never use such a build with a real key.
ifeq ($(TEST_BUILD),1)
DEFINES += TEST_BUILD
endif

APP_SOURCE_PATH += src

include $(BOLOS_SDK)/Makefile.standard_app
