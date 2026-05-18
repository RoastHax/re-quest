from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


class CertificateVerificationError(Exception):
    pass


_HASHES: dict[int, hashes.HashAlgorithm] = {
    2: hashes.SHA1(),
    4: hashes.SHA256(),
    5: hashes.SHA384(),
    6: hashes.SHA512(),
}

_SIG_SCHEME_HASHES: dict[int, hashes.HashAlgorithm] = {
    0x0804: hashes.SHA256(),
    0x0805: hashes.SHA384(),
    0x0806: hashes.SHA512(),
}


_RSA_PSS = {0x0804, 0x0805, 0x0806}
_EDDSA = {0x0807, 0x0808}


def load_der_chain(chain_der: list[bytes]) -> list[x509.Certificate]:
    try:
        return [x509.load_der_x509_certificate(item) for item in chain_der]
    except Exception as exc:
        raise CertificateVerificationError(f"invalid certificate chain: {exc}") from exc


def verify_certificate_chain(hostname: str, chain_der: list[bytes], verify: bool | str = True) -> list[x509.Certificate]:
    certs = load_der_chain(chain_der)
    if not certs:
        raise CertificateVerificationError("server did not send a certificate")
    leaf = certs[0]
    _verify_validity(leaf)
    _verify_hostname(leaf, hostname)
    if verify is False:
        return certs
    store_certs = _load_trust_store(verify if isinstance(verify, str) else None)
    if not store_certs:
        raise CertificateVerificationError("no CA certificates available for verification")
    try:
        from cryptography.x509.verification import DNSName, IPAddress, PolicyBuilder, Store

        subject: Any
        try:
            subject = IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            subject = DNSName(hostname)
        verifier = (
            PolicyBuilder()
            .store(Store(store_certs))
            .time(datetime.now(timezone.utc))
            .build_server_verifier(subject)
        )
        verifier.verify(leaf, certs[1:])
    except Exception as exc:
        raise CertificateVerificationError(f"certificate chain verification failed: {exc}") from exc
    return certs


def verify_digitally_signed(public_key: Any, sigalg: int, signature: bytes, data: bytes) -> None:
    if sigalg in _EDDSA:
        if sigalg == 0x0807 and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
            return
        if sigalg == 0x0808 and isinstance(public_key, ed448.Ed448PublicKey):
            public_key.verify(signature, data)
            return
        raise CertificateVerificationError(f"signature algorithm 0x{sigalg:04x} does not match certificate key")
    hash_alg = _SIG_SCHEME_HASHES.get(sigalg) or _HASHES.get(sigalg >> 8)
    if hash_alg is None:
        raise CertificateVerificationError(f"unsupported signature hash algorithm 0x{sigalg:04x}")
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if sigalg in _RSA_PSS:
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
                    hash_alg,
                )
            else:
                public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_alg))
        else:
            raise CertificateVerificationError(f"unsupported certificate public key type {type(public_key).__name__}")
    except InvalidSignature as exc:
        raise CertificateVerificationError("server signature verification failed") from exc


def _verify_validity(cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc
    else:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if hasattr(cert, "not_valid_after_utc"):
        not_after = cert.not_valid_after_utc
    else:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before or now > not_after:
        raise CertificateVerificationError("server certificate is not currently valid")


def _verify_hostname(cert: x509.Certificate, hostname: str) -> None:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    names: list[str] = []
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names.extend(str(item) for item in san.get_values_for_type(x509.DNSName))
        ips.extend(san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    if ip is not None:
        if any(item == ip for item in ips):
            return
        raise CertificateVerificationError(f"certificate does not match IP address {hostname}")
    if not names:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.append(attr.value)
    host = hostname.rstrip(".").lower()
    if any(_dnsname_match(pattern, host) for pattern in names):
        return
    raise CertificateVerificationError(f"certificate does not match hostname {hostname}")


def _dnsname_match(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    if "*" not in pattern:
        return pattern == hostname
    parts = pattern.split(".")
    host_parts = hostname.split(".")
    if len(parts) != len(host_parts):
        return False
    if parts[0] != "*":
        return False
    return parts[1:] == host_parts[1:]


def _load_trust_store(cafile: str | None = None) -> list[x509.Certificate]:
    paths: list[Path] = []
    if cafile:
        paths.append(Path(cafile))
    for env_name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        value = os.environ.get(env_name)
        if value:
            paths.append(Path(value))
    paths.extend(
        Path(item)
        for item in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/ca-bundle.pem",
        )
    )
    certs: list[x509.Certificate] = []
    seen: set[Path] = set()
    for path in paths:
        if path in seen or not path.exists():
            continue
        seen.add(path)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.suffix.lower() in {".pem", ".crt", ".cer"}:
                    certs.extend(_load_pem_file(child))
        else:
            certs.extend(_load_pem_file(path))
        if certs:
            break
    return certs


def _load_pem_file(path: Path) -> list[x509.Certificate]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    result: list[x509.Certificate] = []
    for block in re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S):
        try:
            result.append(x509.load_pem_x509_certificate(block))
        except Exception:
            continue
    return result
