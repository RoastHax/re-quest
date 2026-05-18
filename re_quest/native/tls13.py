from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .certs import load_der_chain, verify_certificate_chain, verify_digitally_signed


class TlsError(Exception):
    pass


@dataclass(slots=True)
class CipherSuite:
    suite_id: int
    hashmod: Callable[[], "hashlib._Hash"]
    key_len: int
    iv_len: int = 12


@dataclass(slots=True)
class TrafficKeys:
    key: bytes
    iv: bytes
    secret: bytes
    seq: int = 0


TLS_AES_128_GCM_SHA256 = CipherSuite(0x1301, hashlib.sha256, 16)
TLS_AES_256_GCM_SHA384 = CipherSuite(0x1302, hashlib.sha384, 32)

SUPPORTED_CIPHERS = {
    TLS_AES_128_GCM_SHA256.suite_id: TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384.suite_id: TLS_AES_256_GCM_SHA384,
}


class ChromeTls13Connection:
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
        self.x25519_private = x25519.X25519PrivateKey.generate()
        self.transcript = b""
        self.cipher_suite = TLS_AES_128_GCM_SHA256
        self.client_hs: TrafficKeys | None = None
        self.server_hs: TrafficKeys | None = None
        self.client_app: TrafficKeys | None = None
        self.server_app: TrafficKeys | None = None
        self.selected_alpn: str | None = None
        self.certificate_chain_der: list[bytes] = []

    def handshake(self) -> None:
        client_hello = self._build_client_hello()
        self.transcript += client_hello
        self._send_plain_record(22, client_hello, legacy_version=b"\x03\x01")
        server_hello = self._read_server_hello()
        self.transcript += server_hello
        shared_secret = self._parse_server_hello(server_hello)
        self._derive_handshake_keys(shared_secret)
        self._read_server_encrypted_handshake()
        self._derive_application_keys()
        self._send_client_finished()

    def send_application_data(self, data: bytes) -> None:
        self._send_encrypted_record(23, data, self._require_keys(self.client_app))

    def read_application_data(self) -> tuple[int, bytes]:
        while True:
            record_type, payload, header = self._read_record()
            if record_type == 20:
                continue
            keys = self._require_keys(self.server_app)
            if record_type != 23:
                raise TlsError(f"unexpected post-handshake record type {record_type}")
            inner_type, plaintext = self._decrypt_record(header, payload, keys)
            return inner_type, plaintext

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _build_client_hello(self) -> bytes:
        public_key = self.x25519_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        session_id = os.urandom(32)
        ciphers = [
            0xFAFA,
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xCCA9,
            0xCCA8,
            0xC013,
            0xC014,
            0x009C,
            0x009D,
            0x002F,
            0x0035,
        ]
        extensions = _ordered_extensions(
            self.server_name,
            public_key,
            self.extension_order,
            alpn_protocols=self.alpn_protocols,
        )
        body = b"".join(
            [
                b"\x03\x03",
                os.urandom(32),
                _u8vec(session_id),
                _u16vec(b"".join(struct.pack("!H", item) for item in ciphers)),
                b"\x01\x00",
                _u16vec(b"".join(extensions)),
            ]
        )
        return b"\x01" + len(body).to_bytes(3, "big") + body

    def _read_server_hello(self) -> bytes:
        while True:
            record_type, payload, _ = self._read_record()
            if record_type == 20:
                continue
            if record_type != 22:
                raise TlsError(f"expected ServerHello handshake record, got {record_type}")
            if not payload:
                continue
            msg_type = payload[0]
            msg_len = int.from_bytes(payload[1:4], "big")
            message = payload[: 4 + msg_len]
            if msg_type != 2:
                raise TlsError(f"expected ServerHello, got handshake type {msg_type}")
            return message

    def _parse_server_hello(self, server_hello: bytes) -> bytes:
        body = server_hello[4:]
        pos = 0
        pos += 2 + 32
        session_len = body[pos]
        pos += 1 + session_len
        selected_cipher = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        pos += 1
        self.cipher_suite = SUPPORTED_CIPHERS.get(selected_cipher) or TLS_AES_128_GCM_SHA256
        ext_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = pos + ext_len
        server_key: bytes | None = None
        while pos < end:
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ln = int.from_bytes(body[pos + 2 : pos + 4], "big")
            data = body[pos + 4 : pos + 4 + ln]
            pos += 4 + ln
            if ext_type == 51:
                group = int.from_bytes(data[0:2], "big")
                key_len = int.from_bytes(data[2:4], "big")
                if group != 0x001D:
                    raise TlsError(f"server selected unsupported key share group 0x{group:04x}")
                server_key = data[4 : 4 + key_len]
        if not server_key:
            raise TlsError("ServerHello did not include X25519 key_share")
        peer_public = x25519.X25519PublicKey.from_public_bytes(server_key)
        return self.x25519_private.exchange(peer_public)

    def _derive_handshake_keys(self, shared_secret: bytes) -> None:
        hashmod = self.cipher_suite.hashmod
        hash_len = hashmod().digest_size
        zeros = b"\x00" * hash_len
        early_secret = _hkdf_extract(zeros, zeros, hashmod)
        derived = _derive_secret(early_secret, b"derived", b"", hashmod)
        handshake_secret = _hkdf_extract(derived, shared_secret, hashmod)
        transcript_hash = hashmod(self.transcript).digest()
        client_secret = _derive_secret(handshake_secret, b"c hs traffic", transcript_hash, hashmod, prehashed=True)
        server_secret = _derive_secret(handshake_secret, b"s hs traffic", transcript_hash, hashmod, prehashed=True)
        self.client_hs = self._traffic_keys(client_secret)
        self.server_hs = self._traffic_keys(server_secret)
        self._handshake_secret = handshake_secret

    def _read_server_encrypted_handshake(self) -> None:
        buffer = b""
        while True:
            record_type, payload, header = self._read_record()
            if record_type == 20:
                continue
            if record_type != 23:
                raise TlsError(f"expected encrypted handshake record, got {record_type}")
            inner_type, plaintext = self._decrypt_record(header, payload, self._require_keys(self.server_hs))
            if inner_type != 22:
                continue
            buffer += plaintext
            while len(buffer) >= 4:
                msg_len = int.from_bytes(buffer[1:4], "big")
                if len(buffer) < 4 + msg_len:
                    break
                message = buffer[: 4 + msg_len]
                buffer = buffer[4 + msg_len :]
                msg_type = message[0]
                if msg_type == 8:
                    self._parse_encrypted_extensions(message)
                    self.transcript += message
                elif msg_type == 11:
                    self._parse_certificate(message)
                    self.transcript += message
                elif msg_type == 15:
                    self._verify_certificate_verify(message)
                    self.transcript += message
                elif msg_type == 20:
                    self._verify_server_finished(message)
                    self.transcript += message
                    return
                else:
                    self.transcript += message

    def _parse_encrypted_extensions(self, message: bytes) -> None:
        body = message[4:]
        if len(body) < 2:
            return
        pos = 2
        end = len(body)
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ln = int.from_bytes(body[pos + 2 : pos + 4], "big")
            data = body[pos + 4 : pos + 4 + ln]
            pos += 4 + ln
            if ext_type == 16 and len(data) >= 3:
                name_len = data[2]
                self.selected_alpn = data[3 : 3 + name_len].decode("ascii", errors="replace")

    def _parse_certificate(self, message: bytes) -> None:
        body = message[4:]
        if not body:
            raise TlsError("empty Certificate message")
        pos = 1 + body[0]
        if pos + 3 > len(body):
            raise TlsError("malformed Certificate message")
        total_len = int.from_bytes(body[pos : pos + 3], "big")
        pos += 3
        end = pos + total_len
        chain: list[bytes] = []
        while pos + 3 <= end and pos + 3 <= len(body):
            cert_len = int.from_bytes(body[pos : pos + 3], "big")
            pos += 3
            cert = body[pos : pos + cert_len]
            pos += cert_len
            if pos + 2 > len(body):
                raise TlsError("malformed CertificateEntry extensions")
            ext_len = int.from_bytes(body[pos : pos + 2], "big")
            pos += 2 + ext_len
            chain.append(cert)
        if not chain:
            raise TlsError("server did not send a certificate")
        self.certificate_chain_der = chain
        try:
            verify_certificate_chain(self.server_name, chain, self.verify)
        except Exception as exc:
            raise TlsError(str(exc)) from exc

    def _verify_certificate_verify(self, message: bytes) -> None:
        if not self.certificate_chain_der:
            raise TlsError("CertificateVerify arrived before Certificate")
        body = message[4:]
        if len(body) < 4:
            raise TlsError("malformed CertificateVerify")
        sigalg = int.from_bytes(body[:2], "big")
        sig_len = int.from_bytes(body[2:4], "big")
        signature = body[4 : 4 + sig_len]
        signed_content = (
            b"\x20" * 64
            + b"TLS 1.3, server CertificateVerify"
            + b"\x00"
            + self.cipher_suite.hashmod(self.transcript).digest()
        )
        try:
            cert = load_der_chain(self.certificate_chain_der)[0]
            verify_digitally_signed(cert.public_key(), sigalg, signature, signed_content)
        except Exception as exc:
            raise TlsError(str(exc)) from exc

    def _verify_server_finished(self, message: bytes) -> None:
        hashmod = self.cipher_suite.hashmod
        finished_key = _hkdf_expand_label(
            self._server_handshake_traffic_secret(),
            b"finished",
            b"",
            hashmod().digest_size,
            hashmod,
        )
        expected = hmac.new(finished_key, hashmod(self.transcript).digest(), hashmod).digest()
        verify_data = message[4:]
        if not hmac.compare_digest(expected, verify_data):
            raise TlsError("server Finished verify_data mismatch")

    def _derive_application_keys(self) -> None:
        hashmod = self.cipher_suite.hashmod
        hash_len = hashmod().digest_size
        derived = _derive_secret(self._handshake_secret, b"derived", b"", hashmod)
        master_secret = _hkdf_extract(derived, b"\x00" * hash_len, hashmod)
        transcript_hash = hashmod(self.transcript).digest()
        client_secret = _derive_secret(master_secret, b"c ap traffic", transcript_hash, hashmod, prehashed=True)
        server_secret = _derive_secret(master_secret, b"s ap traffic", transcript_hash, hashmod, prehashed=True)
        self.client_app = self._traffic_keys(client_secret)
        self.server_app = self._traffic_keys(server_secret)

    def _send_client_finished(self) -> None:
        hashmod = self.cipher_suite.hashmod
        finished_key = _hkdf_expand_label(
            self._client_handshake_traffic_secret(),
            b"finished",
            b"",
            hashmod().digest_size,
            hashmod,
        )
        verify_data = hmac.new(finished_key, hashmod(self.transcript).digest(), hashmod).digest()
        message = b"\x14" + len(verify_data).to_bytes(3, "big") + verify_data
        self._send_encrypted_record(22, message, self._require_keys(self.client_hs))
        self.transcript += message

    def _server_handshake_traffic_secret(self) -> bytes:
        return self._traffic_secret(self.server_hs)

    def _client_handshake_traffic_secret(self) -> bytes:
        return self._traffic_secret(self.client_hs)

    def _traffic_secret(self, keys: TrafficKeys | None) -> bytes:
        secret = getattr(keys, "secret", None)
        if secret is None:
            raise TlsError("traffic secret unavailable")
        return secret

    def _traffic_keys(self, secret: bytes) -> TrafficKeys:
        keys = TrafficKeys(
            key=_hkdf_expand_label(secret, b"key", b"", self.cipher_suite.key_len, self.cipher_suite.hashmod),
            iv=_hkdf_expand_label(secret, b"iv", b"", self.cipher_suite.iv_len, self.cipher_suite.hashmod),
            secret=secret,
        )
        return keys

    def _send_plain_record(self, record_type: int, payload: bytes, *, legacy_version: bytes = b"\x03\x03") -> None:
        self.sock.sendall(bytes([record_type]) + legacy_version + len(payload).to_bytes(2, "big") + payload)

    def _send_encrypted_record(self, inner_type: int, payload: bytes, keys: TrafficKeys) -> None:
        plaintext = payload + bytes([inner_type])
        ciphertext_len = len(plaintext) + 16
        header = b"\x17\x03\x03" + ciphertext_len.to_bytes(2, "big")
        nonce = _record_nonce(keys.iv, keys.seq)
        ciphertext = AESGCM(keys.key).encrypt(nonce, plaintext, header)
        keys.seq += 1
        self.sock.sendall(header + ciphertext)

    def _decrypt_record(self, header: bytes, payload: bytes, keys: TrafficKeys) -> tuple[int, bytes]:
        nonce = _record_nonce(keys.iv, keys.seq)
        plaintext = AESGCM(keys.key).decrypt(nonce, payload, header)
        keys.seq += 1
        pos = len(plaintext) - 1
        while pos >= 0 and plaintext[pos] == 0:
            pos -= 1
        if pos < 0:
            raise TlsError("encrypted record has no inner content type")
        return plaintext[pos], plaintext[:pos]

    def _read_record(self) -> tuple[int, bytes, bytes]:
        header = _recv_exact(self.sock, 5)
        record_type = header[0]
        length = int.from_bytes(header[3:5], "big")
        payload = _recv_exact(self.sock, length)
        return record_type, payload, header

    def _require_keys(self, keys: TrafficKeys | None) -> TrafficKeys:
        if keys is None:
            raise TlsError("traffic keys not derived")
        return keys


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        data = sock.recv(remaining)
        if not data:
            raise TlsError("unexpected EOF")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _u8vec(data: bytes) -> bytes:
    return len(data).to_bytes(1, "big") + data


def _u16vec(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _server_name(hostname: str) -> bytes:
    encoded = hostname.encode("idna")
    name = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
    return _u16vec(name)


def _alpn(protocols: list[str]) -> bytes:
    body = b"".join(_u8vec(item.encode("ascii")) for item in protocols)
    return _u16vec(body)


def _signature_algorithms() -> bytes:
    values = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    return _u16vec(b"".join(struct.pack("!H", item) for item in values))


def _ech_grease() -> bytes:
    return b"\x00\x00\x01\x00\x01\x91\x00\x20" + os.urandom(32) + b"\x00\xf0" + os.urandom(240)


def _key_share(x25519_public_key: bytes) -> bytes:
    grease = struct.pack("!HHB", 0x1A1A, 1, 0)
    hybrid = struct.pack("!HH", 0x11EC, 1216) + os.urandom(1216)
    xkey = struct.pack("!HH", 0x001D, len(x25519_public_key)) + x25519_public_key
    return _u16vec(grease + hybrid + xkey)


def _ordered_extensions(
    server_name: str,
    x25519_public_key: bytes,
    extension_order: tuple[int | str, ...] | None,
    *,
    alpn_protocols: list[str] | None = None,
    supported_versions: list[int] | None = None,
    include_key_share: bool = True,
    include_psk: bool = True,
    include_alps: bool = True,
    include_ech: bool = True,
) -> list[bytes]:
    alpn_protocols = alpn_protocols or ["h2", "http/1.1"]
    versions = supported_versions or [0x9A9A, 0x0304, 0x0303]
    extension_values = {
        13: _signature_algorithms(),
        16: _alpn(alpn_protocols),
        65281: b"\x00",
        18: b"",
        35: b"",
        5: b"\x01\x00\x00\x00\x00",
        43: _u8vec(b"".join(struct.pack("!H", item) for item in versions)),
        11: b"\x01\x00",
        0: _server_name(server_name),
        10: b"\x00\x0a\x1a\x1a\x11\xec\x00\x1d\x00\x17\x00\x18",
        23: b"",
        27: b"\x02\x00\x02",
    }
    if include_ech:
        extension_values[65037] = _ech_grease()
    if include_alps and "h2" in alpn_protocols:
        extension_values[17613] = b"\x00\x03\x02h2"
    if include_psk:
        extension_values[45] = b"\x01\x01"
    if include_key_share:
        extension_values[51] = _key_share(x25519_public_key)
    order = extension_order or (
        "grease_first",
        13,
        16,
        65281,
        18,
        35,
        5,
        43,
        65037,
        11,
        17613,
        0,
        10,
        23,
        27,
        45,
        51,
        "grease_last",
    )
    result = []
    for item in order:
        if item == "grease_first":
            result.append(_extension(0xFAFA, b""))
        elif item == "grease_last":
            result.append(_extension(0x1A1A, b"\x00"))
        elif int(item) in extension_values:
            result.append(_extension(int(item), extension_values[int(item)]))
    return result


def _hkdf_extract(salt: bytes, ikm: bytes, hashmod: Callable[[], "hashlib._Hash"]) -> bytes:
    return hmac.new(salt, ikm, hashmod).digest()


def _hkdf_expand(secret: bytes, info: bytes, length: int, hashmod: Callable[[], "hashlib._Hash"]) -> bytes:
    blocks = []
    output = b""
    counter = 1
    previous = b""
    while len(output) < length:
        previous = hmac.new(secret, previous + info + bytes([counter]), hashmod).digest()
        blocks.append(previous)
        output += previous
        counter += 1
    return output[:length]


def _hkdf_expand_label(
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
    hashmod: Callable[[], "hashlib._Hash"],
) -> bytes:
    full_label = b"tls13 " + label
    info = length.to_bytes(2, "big") + _u8vec(full_label) + _u8vec(context)
    return _hkdf_expand(secret, info, length, hashmod)


def _derive_secret(
    secret: bytes,
    label: bytes,
    messages: bytes,
    hashmod: Callable[[], "hashlib._Hash"],
    *,
    prehashed: bool = False,
) -> bytes:
    digest = messages if prehashed else hashmod(messages).digest()
    return _hkdf_expand_label(secret, label, digest, hashmod().digest_size, hashmod)


def _record_nonce(iv: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(len(iv), "big")
    return bytes(left ^ right for left, right in zip(iv, seq_bytes, strict=True))
