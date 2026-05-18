from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .certs import load_der_chain, verify_certificate_chain, verify_digitally_signed
from .tls13 import TlsError, _alpn, _extension, _recv_exact, _server_name, _signature_algorithms, _u8vec, _u16vec


@dataclass(slots=True)
class Tls12CipherSuite:
    suite_id: int
    hashmod: Callable[[], "hashlib._Hash"]
    key_len: int
    fixed_iv_len: int = 4
    explicit_nonce_len: int = 8
    tag_len: int = 16


@dataclass(slots=True)
class Tls12TrafficKeys:
    key: bytes
    fixed_iv: bytes
    seq: int = 0


TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = Tls12CipherSuite(0xC02B, hashlib.sha256, 16)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = Tls12CipherSuite(0xC02F, hashlib.sha256, 16)
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = Tls12CipherSuite(0xC02C, hashlib.sha384, 32)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = Tls12CipherSuite(0xC030, hashlib.sha384, 32)

SUPPORTED_TLS12_CIPHERS = {
    item.suite_id: item
    for item in (
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    )
}

_CURVES = {
    0x001D: "x25519",
    0x0017: ec.SECP256R1(),
    0x0018: ec.SECP384R1(),
}

class ChromeTls12Connection:
    def __init__(
        self,
        sock: socket.socket,
        server_name: str,
        extension_order: tuple[int | str, ...] | None = None,
        alpn_protocols: list[str] | None = None,
        verify: bool | str = True,
    ) -> None:
        self.sock = sock
        self.server_name = server_name
        self.extension_order = extension_order
        self.alpn_protocols = alpn_protocols or ["h2", "http/1.1"]
        self.verify = verify
        self.client_random = os.urandom(32)
        self.server_random = b""
        self.transcript = b""
        self.cipher_suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        self.selected_alpn: str | None = None
        self.certificate_chain_der: list[bytes] = []
        self._plain_handshake_buffer = b""
        self._encrypted_handshake_buffer = b""
        self._extended_master_secret = False
        self._server_ecdh_group = 0
        self._server_ecdh_public = b""
        self._client_write: Tls12TrafficKeys | None = None
        self._server_write: Tls12TrafficKeys | None = None
        self._master_secret = b""
        self.server_finished_verified = False

    def handshake(self) -> None:
        client_hello = self._build_client_hello()
        self.transcript += client_hello
        self._send_plain_record(22, client_hello, legacy_version=b"\x03\x01")
        server_hello = self._read_plain_handshake_message()
        if server_hello[0] != 2:
            raise TlsError(f"expected ServerHello, got handshake type {server_hello[0]}")
        self._parse_server_hello(server_hello)
        self.transcript += server_hello
        while True:
            message = self._read_plain_handshake_message()
            msg_type = message[0]
            if msg_type == 11:
                self._parse_certificate(message)
                self.transcript += message
            elif msg_type == 12:
                self._parse_server_key_exchange(message)
                self.transcript += message
            elif msg_type == 13:
                raise TlsError("TLS 1.2 client certificates are not implemented")
            elif msg_type == 14:
                self.transcript += message
                break
            else:
                self.transcript += message
        client_key_exchange, pre_master_secret = self._build_client_key_exchange()
        self._send_plain_record(22, client_key_exchange)
        self.transcript += client_key_exchange
        self._derive_keys(pre_master_secret)
        self._send_plain_record(20, b"\x01")
        self._send_client_finished()
        self._read_server_change_cipher_spec()
        self._read_server_finished()

    def send_application_data(self, data: bytes) -> None:
        self._send_encrypted_record(23, data, self._require_client_keys())

    def read_application_data(self) -> tuple[int, bytes]:
        while True:
            record_type, payload, header = self._read_record()
            if record_type == 20:
                continue
            if record_type == 21:
                plaintext = self._decrypt_record(record_type, header[1:3], payload, self._require_server_keys())
                raise TlsError(f"TLS alert received: {plaintext.hex()}")
            if record_type not in {22, 23}:
                continue
            plaintext = self._decrypt_record(record_type, header[1:3], payload, self._require_server_keys())
            return record_type, plaintext

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _build_client_hello(self) -> bytes:
        session_id = os.urandom(32)
        ciphers = [0xFAFA, 0xC02B, 0xC02F, 0xC02C, 0xC030]
        extensions = _ordered_tls12_extensions(self.server_name, self.extension_order, self.alpn_protocols)
        body = b"".join(
            [
                b"\x03\x03",
                self.client_random,
                _u8vec(session_id),
                _u16vec(b"".join(struct.pack("!H", item) for item in ciphers)),
                b"\x01\x00",
                _u16vec(b"".join(extensions)),
            ]
        )
        return b"\x01" + len(body).to_bytes(3, "big") + body

    def _parse_server_hello(self, message: bytes) -> None:
        body = message[4:]
        if len(body) < 38:
            raise TlsError("malformed TLS 1.2 ServerHello")
        pos = 0
        version = body[pos : pos + 2]
        pos += 2
        if version != b"\x03\x03":
            raise TlsError(f"server selected unsupported TLS version {version.hex()}")
        self.server_random = body[pos : pos + 32]
        pos += 32
        session_len = body[pos]
        pos += 1 + session_len
        selected_cipher = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        if selected_cipher not in SUPPORTED_TLS12_CIPHERS:
            raise TlsError(f"server selected unsupported TLS 1.2 cipher 0x{selected_cipher:04x}")
        self.cipher_suite = SUPPORTED_TLS12_CIPHERS[selected_cipher]
        compression = body[pos]
        pos += 1
        if compression != 0:
            raise TlsError("TLS compression is not supported")
        if pos == len(body):
            return
        ext_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ln = int.from_bytes(body[pos + 2 : pos + 4], "big")
            data = body[pos + 4 : pos + 4 + ln]
            pos += 4 + ln
            if ext_type == 16 and len(data) >= 3:
                name_len = data[2]
                self.selected_alpn = data[3 : 3 + name_len].decode("ascii", errors="replace")
            elif ext_type == 23:
                self._extended_master_secret = True

    def _parse_certificate(self, message: bytes) -> None:
        body = message[4:]
        if len(body) < 3:
            raise TlsError("malformed Certificate message")
        total_len = int.from_bytes(body[:3], "big")
        pos = 3
        end = pos + total_len
        chain: list[bytes] = []
        while pos + 3 <= end and pos + 3 <= len(body):
            cert_len = int.from_bytes(body[pos : pos + 3], "big")
            pos += 3
            chain.append(body[pos : pos + cert_len])
            pos += cert_len
        if not chain:
            raise TlsError("server did not send a certificate")
        self.certificate_chain_der = chain
        try:
            verify_certificate_chain(self.server_name, chain, self.verify)
        except Exception as exc:
            raise TlsError(str(exc)) from exc

    def _parse_server_key_exchange(self, message: bytes) -> None:
        body = message[4:]
        if len(body) < 8:
            raise TlsError("malformed ServerKeyExchange")
        pos = 0
        curve_type = body[pos]
        pos += 1
        if curve_type != 3:
            raise TlsError("only named_curve ECDHE parameters are supported")
        group = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        pub_len = body[pos]
        pos += 1
        public_key = body[pos : pos + pub_len]
        pos += pub_len
        params = body[:pos]
        if group not in _CURVES:
            raise TlsError(f"unsupported ECDHE group 0x{group:04x}")
        if pos + 4 > len(body):
            raise TlsError("ServerKeyExchange is missing a TLS 1.2 signature")
        sigalg = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        sig_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        signature = body[pos : pos + sig_len]
        if not self.certificate_chain_der:
            raise TlsError("ServerKeyExchange arrived before Certificate")
        signed = self.client_random + self.server_random + params
        try:
            cert = load_der_chain(self.certificate_chain_der)[0]
            verify_digitally_signed(cert.public_key(), sigalg, signature, signed)
        except Exception as exc:
            raise TlsError(str(exc)) from exc
        self._server_ecdh_group = group
        self._server_ecdh_public = public_key

    def _build_client_key_exchange(self) -> tuple[bytes, bytes]:
        group = self._server_ecdh_group
        if group == 0x001D:
            private = x25519.X25519PrivateKey.generate()
            peer = x25519.X25519PublicKey.from_public_bytes(self._server_ecdh_public)
            shared = private.exchange(peer)
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            curve = _CURVES[group]
            if isinstance(curve, str):
                raise TlsError(f"unsupported ECDHE group 0x{group:04x}")
            private = ec.generate_private_key(curve)
            peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, self._server_ecdh_public)
            shared = private.exchange(ec.ECDH(), peer)
            public = private.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        body = _u8vec(public)
        message = b"\x10" + len(body).to_bytes(3, "big") + body
        return message, shared

    def _derive_keys(self, pre_master_secret: bytes) -> None:
        hashmod = self.cipher_suite.hashmod
        if self._extended_master_secret:
            seed = hashmod(self.transcript).digest()
            master_secret = _tls12_prf(pre_master_secret, b"extended master secret", seed, 48, hashmod)
        else:
            master_secret = _tls12_prf(
                pre_master_secret,
                b"master secret",
                self.client_random + self.server_random,
                48,
                hashmod,
            )
        needed = 2 * (self.cipher_suite.key_len + self.cipher_suite.fixed_iv_len)
        key_block = _tls12_prf(master_secret, b"key expansion", self.server_random + self.client_random, needed, hashmod)
        pos = 0
        client_key = key_block[pos : pos + self.cipher_suite.key_len]
        pos += self.cipher_suite.key_len
        server_key = key_block[pos : pos + self.cipher_suite.key_len]
        pos += self.cipher_suite.key_len
        client_iv = key_block[pos : pos + self.cipher_suite.fixed_iv_len]
        pos += self.cipher_suite.fixed_iv_len
        server_iv = key_block[pos : pos + self.cipher_suite.fixed_iv_len]
        self._master_secret = master_secret
        self._client_write = Tls12TrafficKeys(client_key, client_iv)
        self._server_write = Tls12TrafficKeys(server_key, server_iv)

    def _send_client_finished(self) -> None:
        verify_data = _tls12_finished(
            self._master_secret,
            b"client finished",
            self.transcript,
            self.cipher_suite.hashmod,
        )
        message = b"\x14" + len(verify_data).to_bytes(3, "big") + verify_data
        self._send_encrypted_record(22, message, self._require_client_keys())
        self.transcript += message

    def _read_server_finished(self) -> None:
        message = self._read_encrypted_handshake_message()
        if message[0] != 20:
            raise TlsError(f"expected server Finished, got handshake type {message[0]}")
        expected = _tls12_finished(
            self._master_secret,
            b"server finished",
            self.transcript,
            self.cipher_suite.hashmod,
        )
        self.server_finished_verified = hmac.compare_digest(expected, message[4:])
        if not self.server_finished_verified:
            legacy_seed = hashlib.md5(self.transcript).digest() + hashlib.sha1(self.transcript).digest()
            legacy = _tls12_prf(self._master_secret, b"server finished", legacy_seed, 12, self.cipher_suite.hashmod)
            self.server_finished_verified = hmac.compare_digest(legacy, message[4:])
        self.transcript += message

    def _read_server_change_cipher_spec(self) -> None:
        while True:
            record_type, payload, _ = self._read_record()
            if record_type == 20 and payload == b"\x01":
                return
            if record_type == 21:
                raise TlsError(f"TLS alert received before server Finished: {payload.hex()}")

    def _read_plain_handshake_message(self) -> bytes:
        while True:
            message = self._pop_handshake_message("plain")
            if message is not None:
                return message
            record_type, payload, _ = self._read_record()
            if record_type == 21:
                raise TlsError(f"TLS alert received: {payload.hex()}")
            if record_type != 22:
                continue
            self._plain_handshake_buffer += payload

    def _read_encrypted_handshake_message(self) -> bytes:
        while True:
            message = self._pop_handshake_message("encrypted")
            if message is not None:
                return message
            record_type, payload, header = self._read_record()
            if record_type == 21:
                plaintext = self._decrypt_record(record_type, header[1:3], payload, self._require_server_keys())
                raise TlsError(f"TLS alert received: {plaintext.hex()}")
            if record_type != 22:
                continue
            plaintext = self._decrypt_record(record_type, header[1:3], payload, self._require_server_keys())
            self._encrypted_handshake_buffer += plaintext

    def _pop_handshake_message(self, which: str) -> bytes | None:
        buffer = self._plain_handshake_buffer if which == "plain" else self._encrypted_handshake_buffer
        if len(buffer) < 4:
            return None
        msg_len = int.from_bytes(buffer[1:4], "big")
        if len(buffer) < 4 + msg_len:
            return None
        message = buffer[: 4 + msg_len]
        buffer = buffer[4 + msg_len :]
        if which == "plain":
            self._plain_handshake_buffer = buffer
        else:
            self._encrypted_handshake_buffer = buffer
        return message

    def _send_plain_record(self, record_type: int, payload: bytes, *, legacy_version: bytes = b"\x03\x03") -> None:
        self.sock.sendall(bytes([record_type]) + legacy_version + len(payload).to_bytes(2, "big") + payload)

    def _send_encrypted_record(self, record_type: int, plaintext: bytes, keys: Tls12TrafficKeys) -> None:
        seq = keys.seq.to_bytes(8, "big")
        explicit = seq
        aad = seq + bytes([record_type]) + b"\x03\x03" + len(plaintext).to_bytes(2, "big")
        ciphertext = AESGCM(keys.key).encrypt(keys.fixed_iv + explicit, plaintext, aad)
        keys.seq += 1
        payload = explicit + ciphertext
        self.sock.sendall(bytes([record_type]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload)

    def _decrypt_record(self, record_type: int, version: bytes, payload: bytes, keys: Tls12TrafficKeys) -> bytes:
        if len(payload) < self.cipher_suite.explicit_nonce_len + self.cipher_suite.tag_len:
            raise TlsError("TLS 1.2 AEAD record is too short")
        explicit = payload[: self.cipher_suite.explicit_nonce_len]
        ciphertext = payload[self.cipher_suite.explicit_nonce_len :]
        plaintext_len = len(ciphertext) - self.cipher_suite.tag_len
        seq = keys.seq.to_bytes(8, "big")
        aad = seq + bytes([record_type]) + version + plaintext_len.to_bytes(2, "big")
        plaintext = AESGCM(keys.key).decrypt(keys.fixed_iv + explicit, ciphertext, aad)
        keys.seq += 1
        return plaintext

    def _read_record(self) -> tuple[int, bytes, bytes]:
        header = _recv_exact(self.sock, 5)
        length = int.from_bytes(header[3:5], "big")
        payload = _recv_exact(self.sock, length)
        return header[0], payload, header

    def _require_client_keys(self) -> Tls12TrafficKeys:
        if self._client_write is None:
            raise TlsError("client write keys are unavailable")
        return self._client_write

    def _require_server_keys(self) -> Tls12TrafficKeys:
        if self._server_write is None:
            raise TlsError("server write keys are unavailable")
        return self._server_write


def _ordered_tls12_extensions(
    server_name: str,
    extension_order: tuple[int | str, ...] | None,
    alpn_protocols: list[str],
) -> list[bytes]:
    extension_values = {
        13: _signature_algorithms(),
        16: _alpn(alpn_protocols),
        65281: b"\x00",
        18: b"",
        35: b"",
        5: b"\x01\x00\x00\x00\x00",
        43: b"\x02\x03\x03",
        11: b"\x01\x00",
        0: _server_name(server_name),
        10: b"\x00\x08\x1a\x1a\x00\x1d\x00\x17\x00\x18",
        23: b"",
        27: b"\x02\x00\x02",
    }
    order = extension_order or (
        "grease_first",
        35,
        10,
        43,
        11,
        13,
        23,
        18,
        16,
        5,
        0,
        65281,
        27,
        "grease_last",
    )
    result: list[bytes] = []
    for item in order:
        if item == "grease_first":
            result.append(_extension(0xFAFA, b""))
        elif item == "grease_last":
            result.append(_extension(0x1A1A, b"\x00"))
        elif int(item) in extension_values:
            result.append(_extension(int(item), extension_values[int(item)]))
    return result


def _tls12_prf(
    secret: bytes,
    label: bytes,
    seed: bytes,
    out_len: int,
    hashmod: Callable[[], "hashlib._Hash"],
) -> bytes:
    return _p_hash(secret, label + seed, out_len, hashmod)


def _p_hash(secret: bytes, seed: bytes, out_len: int, hashmod: Callable[[], "hashlib._Hash"]) -> bytes:
    output = b""
    a = seed
    while len(output) < out_len:
        a = hmac.new(secret, a, hashmod).digest()
        output += hmac.new(secret, a + seed, hashmod).digest()
    return output[:out_len]


def _tls12_finished(
    master_secret: bytes,
    label: bytes,
    transcript: bytes,
    hashmod: Callable[[], "hashlib._Hash"],
) -> bytes:
    return _tls12_prf(master_secret, label, hashmod(transcript).digest(), 12, hashmod)
