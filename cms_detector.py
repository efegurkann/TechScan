#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Dict, Optional, List
from bs4 import BeautifulSoup
import aiohttp
import yaml

class CMSDetector:
    def __init__(self):
        # CMS imza veritabanı
        self.cms_signatures = {
            'wordpress': {
                'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
                'headers': {'X-Powered-By': r'WordPress'},
                'meta': {'generator': r'WordPress (\d+\.\d+(\.\d+)?)',
                        'html': [r'wp-content/themes/', r'wp-content/plugins/']},
                'cookies': ['wordpress_test_cookie', 'wp-settings-'],
            },
            'joomla': {
                'paths': ['/administrator/', '/components/', '/modules/'],
                'headers': {'X-Powered-By': r'Joomla'},
                'meta': {'generator': r'Joomla! (\d+\.\d+(\.\d+)?)',
                        'html': [r'\/media\/jui\/', r'\/media\/system\/js\/']},
                'cookies': ['joomla_user_state'],
            },
            'drupal': {
                'paths': ['/sites/default/', '/core/', '/modules/'],
                'headers': {'X-Generator': r'Drupal'},
                'meta': {'generator': r'Drupal (\d+\.\d+(\.\d+)?)',
                        'html': [r'sites/all/themes/', r'sites/all/modules/']},
                'cookies': ['Drupal.visitor'],
            }
        }

    async def check_path_existence(self, session: aiohttp.ClientSession, base_url: str, path: str) -> bool:
        """Belirli bir path'in varlığını kontrol eder"""
        try:
            async with session.head(base_url.rstrip('/') + path) as response:
                return response.status == 200
        except:
            return False

    def check_meta_tags(self, html: str) -> Dict[str, str]:
        """Meta etiketlerini kontrol eder"""
        results = {}
        soup = BeautifulSoup(html, 'html.parser')
        
        # Generator meta tag kontrolü
        generator = soup.find('meta', {'name': 'generator'})
        if generator and generator.get('content'):
            results['generator'] = generator['content']
        
        return results

    def check_html_patterns(self, html: str, patterns: List[str]) -> bool:
        """HTML içeriğinde belirli pattern'ları arar"""
        for pattern in patterns:
            if re.search(pattern, html, re.I):
                return True
        return False

    async def detect(self, url: str, html: str, headers: Dict, cookies: Dict) -> Dict:
        """CMS tespiti yapar"""
        results = {
            "detected_cms": None,
            "version": None,
            "confidence": 0,
            "indicators": []
        }

        async with aiohttp.ClientSession() as session:
            for cms_name, signatures in self.cms_signatures.items():
                confidence = 0
                indicators = []

                # Path kontrolleri
                for path in signatures['paths']:
                    if await self.check_path_existence(session, url, path):
                        confidence += 20
                        indicators.append(f"Path bulundu: {path}")

                # Header kontrolleri
                for header, pattern in signatures['headers'].items():
                    if header in headers and re.search(pattern, headers[header], re.I):
                        confidence += 25
                        indicators.append(f"Header eşleşti: {header}")

                # Meta tag kontrolleri
                meta_info = self.check_meta_tags(html)
                if 'generator' in meta_info:
                    for meta_type, pattern in signatures['meta'].items():
                        if meta_type == 'generator':
                            match = re.search(pattern, meta_info['generator'], re.I)
                            if match:
                                confidence += 30
                                indicators.append("Generator meta tag eşleşti")
                                if match.group(1):  # Versiyon bilgisi
                                    results["version"] = match.group(1)

                # HTML pattern kontrolleri
                if self.check_html_patterns(html, signatures['meta']['html']):
                    confidence += 15
                    indicators.append("HTML içerik pattern'ları eşleşti")

                # Cookie kontrolleri
                for cookie in signatures['cookies']:
                    if any(cookie in c for c in cookies.keys()):
                        confidence += 10
                        indicators.append(f"Cookie eşleşti: {cookie}")

                if confidence > results["confidence"]:
                    results["detected_cms"] = cms_name
                    results["confidence"] = confidence
                    results["indicators"] = indicators

        return results 