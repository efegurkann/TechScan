#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import aiohttp
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
import json
from bs4 import BeautifulSoup

class JSAnalyzer:
    def __init__(self):
        # Bilinen JavaScript kütüphaneleri ve sürüm tespit pattern'ları
        self.known_libraries = {
            'jquery': {
                'patterns': [
                    r'jQuery\s*(?:v|version|Ver|Version)?\s*[\'"]?([0-9]+(?:\.[0-9]+)+)',
                    r'jquery-([0-9]+(?:\.[0-9]+)+)\.min\.js'
                ],
                'cdn_urls': ['code.jquery.com', 'ajax.googleapis.com/ajax/libs/jquery']
            },
            'react': {
                'patterns': [
                    r'React\s*(?:v|version)?\s*[\'"]?([0-9]+(?:\.[0-9]+)+)',
                    r'react(?:-dom)?(?:\.production)?\.min\.js\?v=([0-9]+(?:\.[0-9]+)+)'
                ],
                'cdn_urls': ['unpkg.com/react', 'cdnjs.cloudflare.com/ajax/libs/react']
            },
            'vue': {
                'patterns': [
                    r'Vue\.version\s*=\s*[\'"]([0-9]+(?:\.[0-9]+)+)',
                    r'vue(?:\.min)?\.js\?v=([0-9]+(?:\.[0-9]+)+)'
                ],
                'cdn_urls': ['unpkg.com/vue', 'cdn.jsdelivr.net/npm/vue']
            },
            'angular': {
                'patterns': [
                    r'angular(?:\.min)?\.js\?v=([0-9]+(?:\.[0-9]+)+)',
                    r'Angular\s*(?:v|version)?\s*[\'"]?([0-9]+(?:\.[0-9]+)+)'
                ],
                'cdn_urls': ['ajax.googleapis.com/ajax/libs/angularjs']
            }
        }

        # Güvenlik riski içerebilecek JavaScript fonksiyonları
        self.risk_patterns = {
            'eval_usage': {
                'pattern': r'eval\s*\(',
                'risk': 'Yüksek',
                'description': 'eval() kullanımı tespit edildi. Kod enjeksiyonu riski.'
            },
            'document_write': {
                'pattern': r'document\.write\s*\(',
                'risk': 'Orta',
                'description': 'document.write() kullanımı tespit edildi. XSS riski.'
            },
            'innerHTML': {
                'pattern': r'\.innerHTML\s*=',
                'risk': 'Orta',
                'description': 'innerHTML kullanımı tespit edildi. XSS riski.'
            },
            'settimeout_string': {
                'pattern': r'setTimeout\s*\(\s*[\'"]',
                'risk': 'Orta',
                'description': 'setTimeout ile string parametre kullanımı tespit edildi. Kod enjeksiyonu riski.'
            },
            'inline_script': {
                'pattern': r'<script[^>]*>[\s\S]*?<\/script>',
                'risk': 'Düşük',
                'description': 'Inline script kullanımı tespit edildi. CSP bypass riski.'
            }
        }

    async def fetch_js_content(self, session: aiohttp.ClientSession, url: str) -> str:
        """JavaScript dosyasının içeriğini indirir"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            print(f"JS dosyası indirme hatası ({url}): {str(e)}")
        return ""

    def detect_library_version(self, content: str, url: str) -> List[Dict]:
        """JavaScript kütüphane ve versiyonlarını tespit eder"""
        detected_libs = []

        for lib_name, lib_info in self.known_libraries.items():
            # URL kontrolü
            if any(cdn in url.lower() for cdn in lib_info['cdn_urls']):
                # Pattern kontrolü
                for pattern in lib_info['patterns']:
                    match = re.search(pattern, content)
                    if match:
                        detected_libs.append({
                            'name': lib_name,
                            'version': match.group(1),
                            'url': url,
                            'detection_method': 'pattern_match'
                        })
                        break

        return detected_libs

    def analyze_security_risks(self, content: str, url: str) -> List[Dict]:
        """JavaScript kodunda güvenlik risklerini analiz eder"""
        risks = []

        for risk_name, risk_info in self.risk_patterns.items():
            matches = re.finditer(risk_info['pattern'], content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                risks.append({
                    'type': risk_name,
                    'risk_level': risk_info['risk'],
                    'description': risk_info['description'],
                    'location': {
                        'url': url,
                        'line': line_number
                    }
                })

        return risks

    def extract_endpoints(self, content: str) -> Set[str]:
        """JavaScript kodundan API endpoint'lerini çıkarır"""
        endpoints = set()
        
        # AJAX istekleri için pattern'lar
        patterns = [
            r'(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\([\'"]([^\'")]+)[\'"]',
            r'\$\.(?:get|post|ajax)\s*\(\s*[\'"]([^\'")]+)[\'"]',
            r'new\s+XMLHttpRequest\(\)[\s\S]*?\.open\s*\([\'"][^\'")]+[\'"]\s*,\s*[\'"]([^\'")]+)[\'"]'
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(1)
                if endpoint and not endpoint.startswith(('http://', 'https://', '//')):
                    endpoints.add(endpoint)

        return endpoints

    async def analyze_script(self, session: aiohttp.ClientSession, script_url: str, base_url: str) -> Dict:
        """Tek bir JavaScript dosyasını analiz eder"""
        full_url = urljoin(base_url, script_url)
        content = await self.fetch_js_content(session, full_url)
        
        if not content:
            return None

        return {
            'url': full_url,
            'libraries': self.detect_library_version(content, full_url),
            'security_risks': self.analyze_security_risks(content, full_url),
            'endpoints': list(self.extract_endpoints(content)),
            'size': len(content),
            'minified': '.min.' in script_url.lower() or len(content.splitlines()) < 5
        }

    async def analyze_page(self, url: str, html: str) -> Dict:
        """Sayfadaki tüm JavaScript kaynaklarını analiz eder"""
        results = {
            'scripts': [],
            'total_size': 0,
            'security_risks': [],
            'libraries': [],
            'endpoints': set()
        }

        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script', src=True)

        async with aiohttp.ClientSession() as session:
            for script in scripts:
                src = script.get('src', '')
                if src:
                    analysis = await self.analyze_script(session, src, url)
                    if analysis:
                        results['scripts'].append(analysis)
                        results['total_size'] += analysis['size']
                        results['security_risks'].extend(analysis['security_risks'])
                        results['libraries'].extend(analysis['libraries'])
                        results['endpoints'].update(analysis['endpoints'])

            # Inline script analizi
            for script in soup.find_all('script', src=False):
                content = script.string or ''
                if content.strip():
                    risks = self.analyze_security_risks(content, url)
                    if risks:
                        results['security_risks'].extend(risks)

        results['endpoints'] = list(results['endpoints'])
        return results 