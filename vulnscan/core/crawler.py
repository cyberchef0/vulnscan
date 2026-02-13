#!/usr/bin/env python3
"""
Web crawler for discovering URLs and forms
"""

from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re

from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, http_client, max_pages=50, exclude_patterns=None, include_patterns=None):
        self.http = http_client
        self.max_pages = max_pages
        self.exclude_patterns = exclude_patterns or []
        self.include_patterns = include_patterns or []
        
    def crawl(self, start_url):
        """BFS crawl to discover URLs and forms"""
        visited = set()
        queue = deque([start_url])
        forms = []
        
        base_domain = urlparse(start_url).netloc
        
        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            
            if url in visited:
                continue
                
            # Check exclusion patterns
            if self._should_exclude(url):
                continue
                
            visited.add(url)
            
            # Fetch page
            response = self.http.get(url)
            if not response or not response.text:
                continue
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            page_forms = self._extract_forms(soup, url)
            forms.extend(page_forms)
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href'].strip()
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                    
                full_url = urljoin(url, href)
                
                # Only crawl same domain
                if urlparse(full_url).netloc != base_domain:
                    continue
                    
                # Remove fragments
                full_url = full_url.split('#')[0]
                
                if full_url not in visited and full_url not in queue:
                    if not self._should_exclude(full_url):
                        queue.append(full_url)
        
        return {
            'urls': list(visited),
            'forms': forms
        }
    
    def _extract_forms(self, soup, page_url):
        """Extract forms from HTML"""
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if not action:
                action = page_url
            else:
                action = urljoin(page_url, action)
            
            method = form.get('method', 'GET').upper()
            
            # Extract input fields
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                
                if input_name:
                    input_value = input_tag.get('value', '')
                    
                    # Get default values for select
                    if input_tag.name == 'select':
                        options = input_tag.find_all('option')
                        if options:
                            selected = input_tag.find('option', selected=True)
                            if selected:
                                input_value = selected.get('value', '')
                            else:
                                input_value = options[0].get('value', '')
                    
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value
                    })
            
            forms.append({
                'type': 'form',
                'action': action,
                'method': method,
                'params': inputs
            })
        
        return forms
    
    def _should_exclude(self, url):
        """Check if URL should be excluded"""
        for pattern in self.exclude_patterns:
            if re.search(pattern, url):
                return True
        return False