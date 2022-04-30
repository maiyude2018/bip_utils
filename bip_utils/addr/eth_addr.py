# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Module for Ethereum address encoding/decoding."""

# Imports
from typing import Any, Union
from bip_utils.addr.addr_dec_utils import AddrDecUtils
from bip_utils.addr.addr_key_validator import AddrKeyValidator
from bip_utils.addr.iaddr_decoder import IAddrDecoder
from bip_utils.addr.iaddr_encoder import IAddrEncoder
from bip_utils.coin_conf import CoinsConf
from bip_utils.ecc import IPublicKey
from bip_utils.utils.misc import BytesUtils, CryptoUtils
import binascii
from bip_utils.bech32.bech32_base import Bech32BaseUtils


class EthAddrConst:
    """Class container for Ethereum address constants."""

    # Start byte
    START_BYTE: int = 24
    # Address length
    ADDR_LEN: int = 40


class _EthAddrUtils:
    """Class container for Ethereum address utility functions."""

    @staticmethod
    def ChecksumEncode(addr: str) -> str:
        """
        Checksum encode the specified address.

        Args:
            addr (str): Address string

        Returns:
            str: Checksum encoded address
        """

        # Compute address digest
        addr_hex_digest = BytesUtils.ToHexString(CryptoUtils.Kekkak256(addr.lower()))
        # Encode it
        enc_addr = [c.upper() if (int(addr_hex_digest[i], 16) >= 8) else c.lower() for i, c in enumerate(addr)]

        return "".join(enc_addr)


class EthAddrDecoder(IAddrDecoder):
    """
    Ethereum address decoder class.
    It allows the Ethereum address decoding.
    """

    @staticmethod
    def DecodeAddr(addr: str,
                   **kwargs: Any) -> bytes:
        """
        Decode an Ethereum address to bytes.

        Args:
            addr (str): Address string

        Other Parameters:
            skip_chksum_enc (bool, optional): True to skip checksum encoding verification, false otherwise (default)

        Returns:
            bytes: Public key hash bytes

        Raises:
            ValueError: If the address encoding is not valid
        """
        skip_chksum_enc = kwargs.get("skip_chksum_enc", False)

        # Validate and remove prefix
        addr_no_prefix = AddrDecUtils.ValidateAndRemovePrefix(addr,
                                                              CoinsConf.Ethereum.Params("addr_prefix"))
        # Validate length
        AddrDecUtils.ValidateLength(addr_no_prefix, EthAddrConst.ADDR_LEN)
        # Check checksum encoding
        if not skip_chksum_enc and addr_no_prefix != _EthAddrUtils.ChecksumEncode(addr_no_prefix):
            raise ValueError("Invalid checksum encode")

        return BytesUtils.FromHexString(addr_no_prefix)


class EthAddrEncoder(IAddrEncoder):
    """
    Ethereum address encoder class.
    It allows the Ethereum address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Ethereum address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            skip_chksum_enc (bool, optional): True to skip checksum encoding, false otherwise (default)

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        skip_chksum_enc = kwargs.get("skip_chksum_enc", False)

        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)
        #from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
        #hrp="evmos"
        #evmos_add=Bech32Encoder.Encode(hrp,CryptoUtils.Hash160(pub_key_obj.RawCompressed().ToBytes()))
        #print(evmos_add)

        # First byte of the uncompressed key (i.e. 0x04) is not needed
        kekkak_hex = BytesUtils.ToHexString(CryptoUtils.Kekkak256(pub_key_obj.RawUncompressed().ToBytes()[1:]))
        addr = kekkak_hex[EthAddrConst.START_BYTE:]
        return CoinsConf.Ethereum.Params("addr_prefix") + (_EthAddrUtils.ChecksumEncode(addr)
                                                           if not skip_chksum_enc
                                                           else addr)

class EvmosAddrEncoder(IAddrEncoder):
    """
    Ethereum address encoder class.
    It allows the Ethereum address encoding.
    """

    @staticmethod
    def EncodeKey(pub_key: Union[bytes, IPublicKey],
                  **kwargs: Any) -> str:
        """
        Encode a public key to Ethereum address.

        Args:
            pub_key (bytes or IPublicKey): Public key bytes or object

        Other Parameters:
            skip_chksum_enc (bool, optional): True to skip checksum encoding, false otherwise (default)

        Returns:
            str: Address string

        Raised:
            ValueError: If the public key is not valid
            TypeError: If the public key is not secp256k1
        """
        skip_chksum_enc = kwargs.get("skip_chksum_enc", False)

        pub_key_obj = AddrKeyValidator.ValidateAndGetSecp256k1Key(pub_key)
        #from bip_utils.bech32 import Bech32ChecksumError, Bech32Decoder, Bech32Encoder
        #hrp="evmos"
        #evmos_add=Bech32Encoder.Encode(hrp,CryptoUtils.Hash160(pub_key_obj.RawCompressed().ToBytes()))
        #print(evmos_add)

        # First byte of the uncompressed key (i.e. 0x04) is not needed
        kekkak_hex = BytesUtils.ToHexString(CryptoUtils.Kekkak256(pub_key_obj.RawUncompressed().ToBytes()[1:]))
        addr = kekkak_hex[EthAddrConst.START_BYTE:]
        array = binascii.unhexlify(addr)
        words = [x for x in array]
        bech32_words = Bech32BaseUtils.ConvertBits(words, 8, 5)
        bech32_address = Bech32BaseUtils.evmos_bech32_encode("evmos", bech32_words, 1)
        #bech32_address = bech32_encode("evmos", bech32_words, 1)

        return [CoinsConf.Ethereum.Params("addr_prefix") + (_EthAddrUtils.ChecksumEncode(addr)
                                                           if not skip_chksum_enc
                                                           else addr),bech32_address]








class EthAddr(EthAddrEncoder):
    """
    Ethereum address class.
    Only kept for compatibility, EthAddrEncoder shall be used instead.
    """
