#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import socket
import datetime
import asyncio
from typing import Dict, List, Optional
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import OpenSSL.SSL
from urllib.parse import urlparse

class SSLAnalyzer:
    def __init__(self):
        # Desteklenen protokoller
        self.protocols = {}
        
        # Mevcut protokolleri kontrol et ve ekle
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            self.protocols[ssl.PROTOCOL_TLSv1] = "TLSv1.0"
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            self.protocols[ssl.PROTOCOL_TLSv1_1] = "TLSv1.1"
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            self.protocols[ssl.PROTOCOL_TLSv1_2] = "TLSv1.2"
        # TLS 1.3 için özel kontrol
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.protocols[ssl.PROTOCOL_TLS] = "TLSv1.3"
        except (AttributeError, ValueError):
            pass

        # Zayıf cipher suite'ler
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL',
            'EXPORT', 'anon', 'CBC'
        ]

        # Önerilen minimum anahtar uzunlukları
        self.min_key_sizes = {
            'RSA': 2048,
            'DSA': 2048,
            'EC': 256
        }

    def _get_domain_and_port(self, url: str) -> tuple:
        """URL'den domain ve port bilgisini çıkarır"""
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return domain, port

    def check_protocol_support(self, domain: str, port: int) -> Dict[str, bool]:
        """Desteklenen SSL/TLS protokollerini kontrol eder"""
        results = {}
        
        for protocol in self.protocols.items():
            try:
                context = ssl.SSLContext(protocol[0])
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        results[protocol[1]] = True
            except:
                results[protocol[1]] = False
        
        # TLS 1.3 için özel kontrol
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    results["TLSv1.3"] = True
        except:
            results["TLSv1.3"] = False
        
        return results

    def get_certificate_info(self, domain: str, port: int) -> Dict:
        """Sertifika bilgilerini alır"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = cryptography.x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Sertifika detayları
                    subject = cert.subject
                    issuer = cert.issuer
                    
                    return {
                        'subject': {
                            'common_name': subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                            'organization': subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
                        },
                        'issuer': {
                            'common_name': issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                            'organization': issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
                        },
                        'version': cert.version.value,
                        'serial_number': cert.serial_number,
                        'not_before': cert.not_valid_before_utc.isoformat(),
                        'not_after': cert.not_valid_after_utc.isoformat(),
                        'key_size': cert.public_key().key_size,
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'san': [
                            san.value for san in cert.extensions.get_extension_for_oid(
                                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            ).value
                        ] if cert.extensions.get_extension_for_oid(
                            cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        ) else []
                    }
        except Exception as e:
            return {
                'error': str(e)
            }

    def get_cipher_suites(self, domain: str, port: int) -> List[Dict]:
        """Desteklenen cipher suite'leri alır"""
        ciphers = []
        
        try:
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_METHOD)
            conn = OpenSSL.SSL.Connection(context, socket.socket())
            conn.set_connect_state()
            conn.set_tlsext_host_name(domain.encode())
            conn.connect((domain, port))
            
            cipher_list = conn.get_cipher_list()
            for cipher in cipher_list:
                # Eğer cipher zaten string ise decode etme
                cipher_str = cipher if isinstance(cipher, str) else cipher.decode()
                ciphers.append({
                    'name': cipher_str,
                    'strength': 'Zayıf' if any(weak in cipher_str for weak in self.weak_ciphers) else 'Güçlü'
                })
            
            conn.close()
        except Exception as e:
            print(f"Cipher suite analiz hatası: {str(e)}")
        
        return ciphers

    def analyze_security_level(self, cert_info: Dict, protocols: Dict, ciphers: List[Dict]) -> Dict:
        """SSL/TLS güvenlik seviyesini analiz eder"""
        issues = []
        recommendations = []
        security_score = 100

        # Protokol kontrolü
        if protocols.get('TLSv1.0', False) or protocols.get('TLSv1.1', False):
            issues.append("Eski TLS versiyonları (1.0/1.1) aktif")
            recommendations.append("TLS 1.0 ve 1.1'i devre dışı bırakın")
            security_score -= 20

        # Sertifika kontrolü
        if cert_info.get('error'):
            issues.append(f"Sertifika hatası: {cert_info['error']}")
            security_score = 0
        else:
            try:
                # Süre kontrolü
                not_after = datetime.datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))
                if not_after < datetime.datetime.now(datetime.timezone.utc):
                    issues.append("Sertifika süresi dolmuş")
                    security_score -= 50
                elif (not_after - datetime.datetime.now(datetime.timezone.utc)).days < 30:
                    issues.append("Sertifika süresi 30 günden az kalmış")
                    recommendations.append("Sertifikayı yenileyin")
                    security_score -= 10
            except Exception as e:
                issues.append(f"Sertifika tarih analizi hatası: {str(e)}")

            # Anahtar uzunluğu kontrolü
            key_size = cert_info['key_size']
            if 'RSA' in cert_info['signature_algorithm']:
                if key_size < self.min_key_sizes['RSA']:
                    issues.append(f"RSA anahtar uzunluğu yetersiz ({key_size} bits)")
                    recommendations.append(f"Minimum {self.min_key_sizes['RSA']} bit RSA anahtarı kullanın")
                    security_score -= 20

        # Cipher suite kontrolü
        weak_cipher_count = len([c for c in ciphers if c['strength'] == 'Zayıf'])
        if weak_cipher_count > 0:
            issues.append(f"{weak_cipher_count} zayıf cipher suite aktif")
            recommendations.append("Zayıf cipher suite'leri devre dışı bırakın")
            security_score -= (weak_cipher_count * 5)

        return {
            'score': max(0, security_score),
            'issues': issues,
            'recommendations': recommendations
        }

    async def analyze(self, url: str) -> Dict:
        """SSL/TLS analizi yapar"""
        domain, port = self._get_domain_and_port(url)
        
        # Paralel analiz
        loop = asyncio.get_event_loop()
        cert_info = await loop.run_in_executor(None, self.get_certificate_info, domain, port)
        protocols = await loop.run_in_executor(None, self.check_protocol_support, domain, port)
        ciphers = await loop.run_in_executor(None, self.get_cipher_suites, domain, port)
        
        # Güvenlik analizi
        security_analysis = self.analyze_security_level(cert_info, protocols, ciphers)
        
        return {
            'certificate': cert_info,
            'protocols': protocols,
            'cipher_suites': ciphers,
            'security_analysis': security_analysis
        } 