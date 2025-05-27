#!/usr/bin/env python3
"""
DirBrute - Professional Directory Discovery Tool
Created by kasau
"""

import requests
import argparse
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import logging
import random
import json
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DirectoryBruteforcer:
    def __init__(self, base_url: str, wordlist_file: str, threads: int = 10, 
                 delay: float = 0, output_file: str = 'found_dirs.txt',
                 user_agents: str = None, cookies: str = None, 
                 extensions: List[str] = None, ignore_codes: List[int] = None):
        """
        Initialize the bruteforcer with configuration
        
        Args:
            base_url: Target URL to scan
            wordlist_file: Path to wordlist file
            threads: Number of concurrent threads
            delay: Delay between requests in seconds
            output_file: File to save results
            user_agents: Custom user agents file
            cookies: Cookies to include in requests
            extensions: File extensions to try
            ignore_codes: HTTP status codes to ignore
        """
        self.base_url = base_url.rstrip('/')
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.delay = delay
        self.output_file = output_file
        self.found = []
        self.session = requests.Session()
        self.user_agents = self._load_user_agents(user_agents)
        self.cookies = self._parse_cookies(cookies)
        self.extensions = extensions or ['']
        self.ignore_codes = ignore_codes or []
        
        # Set up session with headers and timeout
        self._configure_session()

    def _configure_session(self) -> None:
        """Configure the HTTP session with headers and settings"""
        headers = {
            'User-Agent': random.choice(self.user_agents) if self.user_agents 
                         else 'DirBrute/2.0 (by kasau)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        self.session.headers.update(headers)
        
        if self.cookies:
            self.session.cookies.update(self.cookies)
        
        # Configure retry strategy
        retry_adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=self.threads,
            pool_maxsize=self.threads
        )
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)

    def _load_user_agents(self, ua_file: str = None) -> List[str]:
        """Load custom user agents from file"""
        default_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'DirBrute/2.0 (by kasau)'
        ]
        
        if not ua_file:
            return default_agents
            
        try:
            with open(ua_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            logger.warning("Failed to load user agents file, using defaults")
            return default_agents

    def _parse_cookies(self, cookies_str: str = None) -> Dict[str, str]:
        """Parse cookies string into dictionary"""
        if not cookies_str:
            return {}
            
        try:
            return dict(cookie.split('=') for cookie in cookies_str.split(';'))
        except Exception:
            logger.warning("Failed to parse cookies string")
            return {}

    def validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def load_wordlist(self) -> List[str]:
        """Load and validate wordlist from file"""
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Loaded {len(wordlist)} words from {self.wordlist_file}")
            
            # Generate variations with extensions
            extended_wordlist = []
            for word in wordlist:
                for ext in self.extensions:
                    if ext and not word.endswith(ext):
                        extended_wordlist.append(f"{word}{ext}")
                    else:
                        extended_wordlist.append(word)
            
            return list(set(extended_wordlist))  # Remove duplicates
            
        except FileNotFoundError:
            logger.error(f"Wordlist file '{self.wordlist_file}' not found")
            return []
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []
    
    def check_url(self, word: str) -> Optional[Dict]:
        """Check if a URL path exists"""
        # Clean the word (remove leading slashes, encode special chars)
        word = word.lstrip('/')
        url = f"{self.base_url}/{word}"
        
        try:
            # Add delay if specified (rate limiting)
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Rotate user agent if available
            if self.user_agents:
                self.session.headers['User-Agent'] = random.choice(self.user_agents)
                
            response = self.session.get(
                url, 
                timeout=10,
                allow_redirects=False,  # Don't follow redirects
                verify=True,  # Verify SSL certificates
                stream=True  # Stream response to save memory
            )
            
            # Check for interesting status codes (excluding ignored codes)
            interesting_codes = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}
            interesting_codes -= set(self.ignore_codes)
            
            if response.status_code in interesting_codes:
                content_length = int(response.headers.get('Content-Length', 0))
                
                # For HEAD requests, we might not get content, so read a small portion
                if content_length == 0:
                    try:
                        content_length = len(response.raw.read(1024))
                    except:
                        content_length = 0
                
                result = {
                    'url': url,
                    'status': response.status_code,
                    'size': content_length,
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'redirect': response.headers.get('Location', '')
                }
                
                print(f"✅ Found: {url} (Status: {response.status_code}, Size: {result['size']} bytes)")
                return result
                
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout accessing {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error accessing {url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error accessing {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error accessing {url}: {e}")
            
        return None
    
    def save_results(self, format: str = 'text') -> None:
        """Save found URLs to file in specified format"""
        if not self.found:
            print("❌ No directories/files found.")
            return
            
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                if format == 'json':
                    json.dump({
                        'target': self.base_url,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'results': self.found
                    }, f, indent=2)
                else:
                    f.write("# Directory Brute-force Results\n")
                    f.write(f"# Target: {self.base_url}\n")
                    f.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Found: {len(self.found)} items\n")
                    f.write("# Format: URL | Status | Size | Content-Type | Redirect\n\n")
                    
                    for item in sorted(self.found, key=lambda x: x['url']):
                        f.write(f"{item['url']} | {item['status']} | {item['size']} | "
                               f"{item['content_type']} | {item['redirect']}\n")
                    
            print(f"💾 Found {len(self.found)} directories/files. Results saved to '{self.output_file}'.")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def run(self) -> None:
        """Main execution method"""
        # Validate base URL
        if not self.validate_url(self.base_url):
            logger.error("Invalid base URL provided")
            return
            
        # Load wordlist
        wordlist = self.load_wordlist()
        if not wordlist:
            logger.error("No valid wordlist loaded")
            return
            
        # Test connectivity to base URL
        try:
            test_response = self.session.head(self.base_url, timeout=10)
            logger.info(f"Target is reachable (Status: {test_response.status_code})")
        except Exception as e:
            logger.warning(f"Could not reach target URL: {e}")
            if not input("Continue anyway? (y/N): ").lower().startswith('y'):
                return
            
        print(f"🎯 Target: {self.base_url}")
        print(f"📝 Wordlist: {len(wordlist)} entries")
        print(f"🧵 Threads: {self.threads}")
        print(f"⏱️  Delay: {self.delay}s between requests")
        print(f"🛡️ Ignoring codes: {self.ignore_codes}")
        print("🚀 Starting scan...")
        print("=" * 60)
        
        start_time = time.time()
        scanned = 0
        
        # Execute brute-force
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_url, word): word for word in wordlist}
            
            for future in as_completed(futures):
                scanned += 1
                try:
                    result = future.result()
                    if result:
                        self.found.append(result)
                except Exception as e:
                    logger.error(f"Future execution error: {e}")
                
                # Progress reporting
                if scanned % 100 == 0 or scanned == len(wordlist):
                    sys.stdout.write(f"\r📊 Progress: {scanned}/{len(wordlist)} "
                                   f"({(scanned/len(wordlist)*100):.1f}%) | "
                                   f"Found: {len(self.found)}")
                    sys.stdout.flush()
        
        end_time = time.time()
        print("\n" + "=" * 60)
        print(f"⏰ Scan completed in {end_time - start_time:.2f} seconds")
        print(f"🎯 Total requests: {len(wordlist)}")
        print(f"📊 Success rate: {len(self.found)}/{len(wordlist)} ({(len(self.found)/len(wordlist)*100):.1f}%)")
        
        # Save results
        self.save_results('json' if self.output_file.endswith('.json') else 'text')

def print_banner() -> None:
    """Display an attractive banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗ ██╗██████╗     ██████╗ ██████╗ ██╗   ██╗████████╗███████╗██████╗    ║
║  ██╔══██╗██║██╔══██╗    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗   ║
║  ██║  ██║██║██████╔╝    ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██████╔╝   ║
║  ██║  ██║██║██╔══██╗    ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ██╔══██╗   ║
║  ██████╔╝██║██║  ██║    ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗██║  ██║   ║
║  ╚═════╝ ╚═╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝   ║
║                                                                              ║
║                        Professional Directory Discovery                      ║
║                              Version 2.0 (by kasau)                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print("🔍 Intelligent Directory & File Discovery Tool")
    print("⚡ Multi-threaded | 📊 Detailed Reporting | 🛡️ Respectful Scanning")
    print("=" * 80)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Directory Brute-forcer by kasau')
    parser.add_argument('url', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-w', '--wordlist', default='wordlists/common.txt', 
                       help='Path to wordlist file (default: wordlists/common.txt)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-o', '--output', default='found_dirs.txt',
                       help='Output file (default: found_dirs.txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('-e', '--extensions', nargs='+', default=[''],
                       help='File extensions to try (e.g., .php .html)')
    parser.add_argument('-a', '--user-agents', 
                       help='File containing user agents to rotate')
    parser.add_argument('-c', '--cookies',
                       help='Cookies to send with requests (format: key1=value1;key2=value2)')
    parser.add_argument('-i', '--ignore-codes', nargs='+', type=int, default=[],
                       help='HTTP status codes to ignore (e.g., 404 403)')
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and run brute-forcer
    brute_forcer = DirectoryBruteforcer(
        base_url=args.url,
        wordlist_file=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        output_file=args.output + ('.json' if args.json else '.txt'),
        user_agents=args.user_agents,
        cookies=args.cookies,
        extensions=args.extensions,
        ignore_codes=args.ignore_codes
    )
    
    try:
        brute_forcer.run()
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        brute_forcer.save_results('json' if args.json else 'text')
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
