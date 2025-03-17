# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
IPATH+=tests
IPATH+=secrets/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
# CRYPTO_EXAMPLE=0

# Enable Crypto Example
CRYPTO_EXAMPLE=1

# wolfssl optimizations and hardening
PROJ_CFLAGS += -DECC_TIMING_RESISTANT  # compile ECC with timing attack resistance
PROJ_CFLAGS += -DTFM_TIMING_RESISTANT
PROJ_CFLAGS += -DWC_RSA_BLINDING
# PROJ_CFLAGS += -DWOLFSSL_SP_SMALL
PROJ_CFLAGS += -DWOLFSSL_SP_MATH_ALL
# PROJ_CFLAGS += -DWOLFSSL_SP_ASM
# PROJ_CFLAGS += -DWC_NO_HARDEN

# wolfssl features
PROJ_CFLAGS += -DNO_RSA
PROJ_CFLAGS += -DHAVE_CHACHA  # compile with CHACHA
PROJ_CFLAGS += -DHAVE_POLY1305  # compile with CHACHA
PROJ_CFLAGS += -DWOLFSSL_PUBLIC_MP
PROJ_CFLAGS += -DHAVE_ECC
PROJ_CFLAGS += -DHAVE_ECC_VERIFY
PROJ_CFLAGS += -DWOLFSSL_CUSTOM_CURVES
PROJ_CFLAGS += -DHAVE_ECC_KOBLITZ
PROJ_CFLAGS += -DHAVE_ED25519
PROJ_CFLAGS += -DWOLFSSL_SHA512
PROJ_CFLAGS += -DHAVE_ED25519_VERIFY
PROJ_CFLAGS += -DHAVE_HKDF
PROJ_CFLAGS += -DWOLFSSL_NO_OPTIONS_H  # make wolfssl shut up
# PROJ_CFLAGS += -DWC_NO_RNG

# PROJ_CFLAGS += -DED25519_PUBLIC_KEY_DEF=
# PROJ_CFLAGS += -DSUBSCRIPTION_KDK_DEF=
# PROJ_CFLAGS += -DEMERGENCY_KEY_DEF=
