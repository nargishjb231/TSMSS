"""TLS/certificate assessment using Python's ssl module (no openssl parsing)."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, CRITICAL, NEEDS_MANUAL
from modules.base import BaseModule

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

WEAK = {"TLSv1.0", "TLSv1.1"}


class SslTlsModule(BaseModule):
    name = "ssl_tls"
    category = "SSL/TLS Security"

    async def run(self, ctx):
        out = []
        host, port = ctx.target.host, ctx.target.port
        chain = await asyncio.get_event_loop().run_in_executor(None, self._fetch_cert, host, port)
        if chain["error"]:
            out.append(self.make(
                ctx, title="TLS handshake with certificate validation failed",
                severity=HIGH, cwe="CWE-295",
                description="A verified handshake to the origin did not succeed, which will "
                            "produce browser warnings for visitors.",
                evidence=f"{host}:{port} -> {chain['error']}",
                detection_method="Verified TLS handshake", confidence=CONFIRMED,
                remediation="Install a complete, trusted certificate chain covering the host.",
                tags=["tls", "certificate"]))
        else:
            out += self._cert_findings(ctx, chain)
        out += await self._protocols(ctx, host, port)
        out += await self._cipher_summary(ctx, host, port)
        return out

    # -- certificate -------------------------------------------------------
    def _fetch_cert(self, host: str, port: int) -> dict:
        result = {"error": None, "der": None, "tls": None, "cipher": None}
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=12) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    result["der"] = tls.getpeercert(binary_form=True)
                    result["tls"] = tls.version()
                    result["cipher"] = (tls.cipher() or (None,))[0]
        except ssl.SSLCertVerificationError as exc:
            result["error"] = f"certificate verification: {exc.verify_message}"
            result["verify_code"] = getattr(exc, "verify_code", None)
        except ssl.SSLError as exc:
            result["error"] = f"TLS error: {exc.reason or exc}"
        except (socket.timeout, OSError) as exc:
            result["error"] = f"connection: {exc}"
        return result

    def _cert_findings(self, ctx, chain: dict) -> list:
        out = []
        info = self._parse(chain["der"])
        if not info:
            return out
        now = datetime.now(timezone.utc)
        not_after, not_before = info.get("not_after"), info.get("not_before")
        if not_after:
            days = (not_after - now).days
            if days < 0:
                out.append(self.make(
                    ctx, title="TLS certificate has expired",
                    severity=CRITICAL, cwe="CWE-298",
                    description=f"Certificate expired {-days} days ago.",
                    evidence=f"notAfter={not_after.isoformat()} subject={info.get('subject')}",
                    detection_method="Certificate validity check", confidence=CONFIRMED,
                    remediation="Renew and redeploy the certificate immediately.",
                    tags=["tls", "certificate"]))
            elif days <= 30:
                out.append(self.make(
                    ctx, title=f"TLS certificate expires in {days} days",
                    severity=MEDIUM if days <= 7 else LOW, cwe="CWE-298",
                    description="Expiry is imminent; renewal automation appears absent.",
                    evidence=f"notAfter={not_after.isoformat()}",
                    detection_method="Certificate validity check", confidence=CONFIRMED,
                    remediation="Renew now and automate renewal.", tags=["tls", "certificate"]))
        if not_before and not_before > now:
            out.append(self.make(
                ctx, title="TLS certificate is not yet valid",
                severity=HIGH, cwe="CWE-295",
                description=f"notBefore is in the future ({not_before.isoformat()}).",
                evidence=f"notBefore={not_before.isoformat()}",
                detection_method="Certificate validity check", confidence=CONFIRMED,
                remediation="Check clock skew on the issuing pipeline.", tags=["tls"]))
        sans = info.get("sans") or []
        if sans and not self._host_matches(ctx.target.host, sans):
            out.append(self.make(
                ctx, title="Certificate does not match the requested hostname",
                severity=HIGH, cwe="CWE-297",
                description=f"Host '{ctx.target.host}' is absent from the SAN list.",
                evidence=f"SANs: {', '.join(sans[:20])}",
                detection_method="SAN comparison", confidence=CONFIRMED,
                remediation="Reissue the certificate with the correct SAN entries.",
                tags=["tls", "certificate"]))
        issuer = info.get("issuer", "")
        if issuer:
            out.append(self.make(
                ctx, title="Certificate issuer identified",
                severity=INFO, cwe="CWE-200",
                description=f"Issued by: {issuer}",
                evidence=f"issuer={issuer}\nsubject={info.get('subject')}",
                detection_method="Certificate parsing", confidence=CONFIRMED,
                remediation="Track the issuing CA for revocation and renewal SLAs.",
                tags=["tls", "inventory"]))
        bits = info.get("key_bits")
        family = info.get("key_family", "")
        if family == "rsa" and bits and bits < 2048:
            out.append(self.make(
                ctx, title=f"Certificate key length is {bits} bits",
                severity=MEDIUM, cwe="CWE-326",
                description="RSA modulus is below the 2048-bit baseline.",
                evidence=f"key=rsa bits={bits}",
                detection_method="Certificate parsing", confidence=CONFIRMED,
                remediation="Reissue with RSA >= 2048 or ECDSA P-256.",
                tags=["tls", "crypto"]))
        sig = (info.get("sig_alg") or "").lower()
        if any(a in sig for a in ("md5", "sha1")):
            out.append(self.make(
                ctx, title=f"Certificate uses weak signature algorithm ({sig})",
                severity=MEDIUM, cwe="CWE-327",
                description="SHA-1/MD5 signatures are deprecated by major trust stores.",
                evidence=f"signature_algorithm={sig}",
                detection_method="Certificate parsing", confidence=CONFIRMED,
                remediation="Reissue with SHA-256 or stronger.", tags=["tls", "crypto"]))
        return out

    @staticmethod
    def _parse(der: bytes | None) -> dict:
        if not der:
            return {}
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()
            bits = getattr(pub, "key_size", None)
            family = ""
            if isinstance(pub, rsa.RSAPublicKey):
                family = "rsa"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                family = "ec"
                bits = pub.curve.key_size
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                family = "ed25519"
            elif isinstance(pub, ed448.Ed448PublicKey):
                family = "ed448"
            sans: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before_utc,
                "not_after": cert.not_valid_after_utc,
                "sans": sans, "key_bits": bits, "key_family": family,
                "sig_alg": cert.signature_algorithm_oid._name,
            }
        except Exception:
            return {}

    @staticmethod
    def _host_matches(host: str, sans: list[str]) -> bool:
        host = host.lower()
        for san in sans:
            san = san.lower()
            if san == host:
                return True
            if san.startswith("*.") and host.count(".") >= 2 and host.split(".", 1)[1] == san[2:]:
                return True
        return False

    # -- protocols ---------------------------------------------------------
    async def _protocols(self, ctx, host: str, port: int):
        loop = asyncio.get_event_loop()
        results = {}
        for label, version in PROTOCOLS:
            results[label] = await loop.run_in_executor(None, self._probe, host, port, version)
        supported = [p for p, ok in results.items() if ok]
        out = []
        if not supported:
            return out
        for weak in sorted(WEAK & set(supported)):
            out.append(self.make(
                ctx, title=f"Deprecated TLS protocol supported ({weak})",
                severity=MEDIUM, cwe="CWE-327",
                description=f"{weak} completed a handshake. Both are deprecated by RFC 8996.",
                evidence=f"Handshake succeeded: {weak}; supported set = {', '.join(supported)}",
                detection_method="Per-version handshake probe", confidence=CONFIRMED,
                remediation="Restrict to TLS 1.2+; disable TLS 1.0/1.1 at the listener.",
                tags=["tls", "protocol"]))
        if "TLSv1.3" not in supported:
            out.append(self.make(
                ctx, title="TLS 1.3 not offered",
                severity=LOW, cwe="CWE-326",
                description="The listener does not negotiate TLS 1.3, forfeiting modern AEAD "
                            "ciphers and a reduced handshake surface.",
                evidence=f"Supported: {', '.join(supported)}",
                detection_method="Per-version handshake probe", confidence=CONFIRMED,
                remediation="Enable TLS 1.3 alongside 1.2.", tags=["tls"]))
        if "TLSv1.2" not in supported and "TLSv1.3" in supported:
            out.append(self.make(
                ctx, title="TLS 1.2 not offered (1.3 only)",
                severity=INFO, cwe="CWE-326",
                description="Very old clients may fail to connect.",
                evidence=f"Supported: {', '.join(supported)}",
                detection_method="Per-version handshake probe", confidence=CONFIRMED,
                remediation="Consider retaining TLS 1.2 for legacy clients.", tags=["tls"]))
        ctx.tls_protocols = supported
        return out

    @staticmethod
    def _probe(host: str, port: int, version) -> bool:
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = version
            c.maximum_version = version
            try:
                c.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=8) as s:
                with c.wrap_socket(s, server_hostname=host):
                    return True
        except (ssl.SSLError, socket.timeout, OSError, ValueError):
            return False

    async def _cipher_summary(self, ctx, host: str, port: int):
        out = []
        loop = asyncio.get_event_loop()
        legacy = await loop.run_in_executor(None, self._legacy_cipher, host, port)
        if legacy:
            out.append(self.make(
                ctx, title=f"Weak cipher negotiated on TLS 1.0/1.1 ({legacy})",
                severity=MEDIUM, cwe="CWE-327",
                description="Legacy protocol negotiated a non-AEAD cipher suite.",
                evidence=f"cipher={legacy}",
                detection_method="Handshake cipher capture", confidence=HIGH_CONF,
                remediation="Remove CBC/RC4/3DES suites from legacy listeners.",
                tags=["tls", "cipher"]))
        return out

    @staticmethod
    def _legacy_cipher(host: str, port: int) -> str | None:
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                c.minimum_version = c.maximum_version = version
                try:
                    c.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((host, port), timeout=8) as s:
                    with c.wrap_socket(s, server_hostname=host) as tls:
                        name = (tls.cipher() or (None,))[0]
                        if name and any(t in name for t in ("CBC", "RC4", "3DES", "DES")):
                            return name
            except (ssl.SSLError, OSError, ValueError):
                continue
        return None