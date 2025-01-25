#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import json
import warnings
from datetime import datetime
from typing import Dict, List, Optional

import aiohttp
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from prettytable import PrettyTable
from Wappalyzer import Wappalyzer, WebPage

# Wappalyzer uyarılarını filtrele
warnings.filterwarnings('ignore', module='Wappalyzer')

from cms_detector import CMSDetector
from vulnerability_scanner import VulnerabilityScanner
from js_analyzer import JSAnalyzer
from ssl_analyzer import SSLAnalyzer

class WebTechFingerprinter:
    def __init__(self, url: str, timeout: int = 30, verbose: bool = False):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.cms_detector = CMSDetector()
        self.vuln_scanner = VulnerabilityScanner()
        self.js_analyzer = JSAnalyzer()
        self.ssl_analyzer = SSLAnalyzer()
        self.results = {
            "url": url,
            "scan_time": datetime.now().isoformat(),
            "headers": {},
            "technologies": [],
            "javascript_libs": [],
            "security_headers": {},
            "potential_vulnerabilities": [],
            "cms_info": {},
            "vulnerabilities": {},
            "javascript_analysis": {},
            "ssl_analysis": {}
        }

    async def analyze_headers(self, response: aiohttp.ClientResponse) -> None:
        """HTTP başlıklarını analiz eder"""
        self.results["headers"] = dict(response.headers)
        
        # Güvenlik başlıklarını kontrol et
        security_headers = {
            "Strict-Transport-Security": "HSTS eksik",
            "Content-Security-Policy": "CSP eksik",
            "X-Frame-Options": "Clickjacking koruması eksik",
            "X-Content-Type-Options": "MIME-sniffing koruması eksik",
            "X-XSS-Protection": "XSS koruması eksik"
        }

        for header, warning in security_headers.items():
            if header not in response.headers:
                self.results["potential_vulnerabilities"].append(warning)
            self.results["security_headers"][header] = response.headers.get(header, "Eksik")

    async def analyze_javascript(self, html: str) -> None:
        """JavaScript analizi yapar"""
        self.results["javascript_analysis"] = await self.js_analyzer.analyze_page(self.url, html)
        
        # JavaScript kütüphanelerini teknolojiler listesine ekle
        for lib in self.results["javascript_analysis"]["libraries"]:
            self.results["technologies"].append({
                "name": lib["name"],
                "version": lib["version"],
                "confidence": 100,
                "source": lib["url"]
            })

        # JavaScript güvenlik risklerini potansiyel zafiyetlere ekle
        for risk in self.results["javascript_analysis"]["security_risks"]:
            self.results["potential_vulnerabilities"].append(
                f"JavaScript Güvenlik Riski ({risk['risk_level']}): {risk['description']} - {risk['location']['url']}:{risk['location']['line']}"
            )

    async def analyze_ssl(self) -> None:
        """SSL/TLS analizi yapar"""
        self.results["ssl_analysis"] = await self.ssl_analyzer.analyze(self.url)
        
        # SSL güvenlik sorunlarını potansiyel zafiyetlere ekle
        for issue in self.results["ssl_analysis"]["security_analysis"]["issues"]:
            self.results["potential_vulnerabilities"].append(f"SSL/TLS Güvenlik Sorunu: {issue}")

    async def detect_technologies(self, html: str) -> None:
        """Wappalyzer kullanarak teknolojileri tespit eder"""
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(self.url)
        detected_apps = wappalyzer.analyze_with_versions(webpage)

        for app_name, app_data in detected_apps.items():
            self.results["technologies"].append({
                "name": app_name,
                "version": app_data.get("version", "Bilinmiyor"),
                "confidence": app_data.get("confidence", 100)
            })

    async def detect_cms(self, response: aiohttp.ClientResponse, html: str) -> None:
        """CMS tespiti yapar"""
        cookies = dict(response.cookies)
        cms_results = await self.cms_detector.detect(self.url, html, dict(response.headers), cookies)
        self.results["cms_info"] = cms_results

        if cms_results["detected_cms"]:
            self.results["technologies"].append({
                "name": cms_results["detected_cms"].title(),
                "version": cms_results["version"] or "Bilinmiyor",
                "confidence": cms_results["confidence"],
                "details": cms_results["indicators"]
            })

    async def scan_vulnerabilities(self) -> None:
        """Tespit edilen teknolojiler için zafiyet taraması yapar"""
        self.results["vulnerabilities"] = await self.vuln_scanner.scan_technologies(
            self.results["technologies"]
        )

    async def scan(self) -> Dict:
        """Ana tarama fonksiyonu"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.url, timeout=self.timeout) as response:
                    html = await response.text()
                    
                    # Paralel analiz
                    await asyncio.gather(
                        self.analyze_headers(response),
                        self.analyze_javascript(html),
                        self.detect_technologies(html),
                        self.detect_cms(response, html),
                        self.analyze_ssl()
                    )
                    
                    # Zafiyet taraması
                    await self.scan_vulnerabilities()
                    
                    return self.results
            
            except Exception as e:
                print(f"{Fore.RED}Hata: {str(e)}{Style.RESET_ALL}")
                return None

def print_results(results: Dict) -> None:
    """Sonuçları terminal'de gösterir"""
    print(f"\n{Fore.GREEN}=== Tarama Sonuçları ==={Style.RESET_ALL}")
    print(f"URL: {results['url']}")
    print(f"Tarama Zamanı: {results['scan_time']}")

    # SSL/TLS Analizi
    if results["ssl_analysis"]:
        print(f"\n{Fore.CYAN}SSL/TLS Analizi:{Style.RESET_ALL}")
        
        # Sertifika bilgileri
        cert = results["ssl_analysis"]["certificate"]
        if not cert.get('error'):
            print("\nSertifika Bilgileri:")
            print(f"Konu: {cert['subject']['common_name']}")
            print(f"Veren: {cert['issuer']['common_name']}")
            print(f"Geçerlilik: {cert['not_before']} - {cert['not_after']}")
            print(f"İmza Algoritması: {cert['signature_algorithm']}")
            print(f"Anahtar Uzunluğu: {cert['key_size']} bits")
            
            if cert['san']:
                print("\nAlternatif İsimler (SAN):")
                for san in cert['san']:
                    print(f"- {san}")
        
        # Protokol desteği
        print("\nProtokol Desteği:")
        for protocol, supported in results["ssl_analysis"]["protocols"].items():
            status = f"{Fore.GREEN}Aktif{Style.RESET_ALL}" if supported else f"{Fore.RED}Pasif{Style.RESET_ALL}"
            print(f"- {protocol}: {status}")
        
        # Cipher suites
        print("\nCipher Suites:")
        cipher_table = PrettyTable()
        cipher_table.field_names = ["Cipher Suite", "Güvenlik"]
        for cipher in results["ssl_analysis"]["cipher_suites"]:
            color = Fore.GREEN if cipher['strength'] == 'Güçlü' else Fore.RED
            cipher_table.add_row([cipher['name'], f"{color}{cipher['strength']}{Style.RESET_ALL}"])
        print(cipher_table)
        
        # Güvenlik analizi
        security = results["ssl_analysis"]["security_analysis"]
        print(f"\nGüvenlik Skoru: {security['score']}/100")
        
        if security['issues']:
            print("\nTespit Edilen Sorunlar:")
            for issue in security['issues']:
                print(f"- {issue}")
        
        if security['recommendations']:
            print("\nÖneriler:")
            for rec in security['recommendations']:
                print(f"- {rec}")

    # JavaScript Analizi
    if results["javascript_analysis"]:
        print(f"\n{Fore.CYAN}JavaScript Analizi:{Style.RESET_ALL}")
        print(f"Toplam Script Boyutu: {results['javascript_analysis']['total_size']/1024:.2f} KB")
        
        if results["javascript_analysis"]["libraries"]:
            print("\nTespit Edilen JS Kütüphaneleri:")
            js_table = PrettyTable()
            js_table.field_names = ["Kütüphane", "Versiyon", "Kaynak"]
            for lib in results["javascript_analysis"]["libraries"]:
                js_table.add_row([lib["name"], lib["version"], lib["url"]])
            print(js_table)
        
        if results["javascript_analysis"]["endpoints"]:
            print("\nTespit Edilen API Endpoint'leri:")
            for endpoint in results["javascript_analysis"]["endpoints"]:
                print(f"- {endpoint}")

    # CMS Bilgisi
    if results["cms_info"]["detected_cms"]:
        print(f"\n{Fore.CYAN}Tespit Edilen CMS:{Style.RESET_ALL}")
        print(f"İsim: {results['cms_info']['detected_cms'].title()}")
        print(f"Versiyon: {results['cms_info']['version'] or 'Bilinmiyor'}")
        print(f"Güven Skoru: %{results['cms_info']['confidence']}")
        print("\nTespit Göstergeleri:")
        for indicator in results['cms_info']['indicators']:
            print(f"- {indicator}")

    # Teknolojiler
    tech_table = PrettyTable()
    tech_table.field_names = ["Teknoloji", "Versiyon", "Güven"]
    for tech in results["technologies"]:
        tech_table.add_row([tech["name"], tech["version"], f"%{tech['confidence']}"])
    print(f"\n{Fore.CYAN}Tespit Edilen Teknolojiler:{Style.RESET_ALL}")
    print(tech_table)

    # Güvenlik Başlıkları
    sec_table = PrettyTable()
    sec_table.field_names = ["Başlık", "Değer"]
    for header, value in results["security_headers"].items():
        sec_table.add_row([header, value])
    print(f"\n{Fore.CYAN}Güvenlik Başlıkları:{Style.RESET_ALL}")
    print(sec_table)

    # Zafiyetler
    if results["vulnerabilities"]:
        print(f"\n{Fore.RED}Tespit Edilen Zafiyetler:{Style.RESET_ALL}")
        for tech_name, vulns in results["vulnerabilities"].items():
            print(f"\n{tech_name}:")
            vuln_table = PrettyTable()
            vuln_table.field_names = ["CVE ID", "Önem", "Skor", "Açıklama"]
            for vuln in vulns:
                vuln_table.add_row([
                    vuln["cve_id"],
                    vuln["severity"],
                    vuln["score"],
                    vuln["description"][:100] + "..." if len(vuln["description"]) > 100 else vuln["description"]
                ])
            print(vuln_table)

    # Potansiyel Güvenlik Açıkları
    if results["potential_vulnerabilities"]:
        print(f"\n{Fore.RED}Potansiyel Güvenlik Açıkları:{Style.RESET_ALL}")
        for vuln in results["potential_vulnerabilities"]:
            print(f"- {vuln}")

def main():
    parser = argparse.ArgumentParser(description="Web Teknoloji Parmak İzi Çıkarma Aracı")
    parser.add_argument("-u", "--url", required=True, help="Taranacak URL")
    parser.add_argument("-o", "--output", help="Çıktı dosyası (JSON)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="İstek zaman aşımı (saniye)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı modu")
    
    args = parser.parse_args()
    
    # Colorama başlatma
    init()

    # Tarayıcı oluştur ve çalıştır
    scanner = WebTechFingerprinter(args.url, args.timeout, args.verbose)
    results = asyncio.run(scanner.scan())

    if results:
        # Sonuçları göster
        print_results(results)

        # JSON çıktısı kaydet
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            print(f"\n{Fore.GREEN}Sonuçlar {args.output} dosyasına kaydedildi.{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 