#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import sys
import base64

import asn1tools
from eth_account import Account
from eth_account._utils.signing import (
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
)
from web3.auto import w3


handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s"
)
handler.setFormatter(formatter)

_logger = logging.getLogger("app")
_logger.setLevel(os.getenv("LOGGING_LEVEL", "WARNING"))
_logger.addHandler(handler)

# max value on curve / https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
SECP256_K1_N = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)


def calc_eth_address(pub_key: bytes) -> str:
    SUBJECT_ASN = """
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    """

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode("SubjectPublicKeyInfo", pub_key)

    pub_key_raw = key_decoded["subjectPublicKey"][0]
    pub_key = pub_key_raw[1 : len(pub_key_raw)]

    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    hex_address = w3.keccak(bytes(pub_key)).hex()
    eth_address = "0x{}".format(hex_address[-40:])

    eth_checksum_addr = w3.toChecksumAddress(eth_address)

    return eth_checksum_addr


base64_key = sys.argv[1]
binary_key = base64.b64decode(base64_key)
print(calc_eth_address(binary_key))
