"""
سیستم فیلترینگ پیشرفته برای پروکسی‌ها
config_filter.py
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from functools import lru_cache
import requests

logger = logging.getLogger(__name__)


class ConfigFilter:
    """سیستم فیلترینگ پیشرفته"""
    
    def __init__(self, settings):
        """
        Args:
            settings: ماژول user_settings
        """
        self.settings = settings
        self.geoip_cache = {}  # Cache برای کشورها
        
    def extract_config_info(self, config: str) -> Optional[Dict]:
        """
        استخراج اطلاعات از کانفیگ
        
        Returns:
            {
                'protocol': 'vless',
                'server': 'example.com',
                'port': 443,
                'country': 'US'
            }
        """
        try:
            # تشخیص پروتکل
            protocol = None
            for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 
                         'hysteria2://', 'hy2://', 'tuic://', 'wireguard://']:
                if config.startswith(proto):
                    protocol = proto.replace('://', '')
                    if protocol == 'hy2':
                        protocol = 'hysteria2'
                    break
            
            if not protocol:
                return None
            
            # استخراج server و port
            parsed = urlparse(config)
            server = parsed.hostname
            port = parsed.port
            
            if not server:
                # برای Shadowsocks که فرمت متفاوته
                if protocol == 'ss':
                    server, port = self._extract_ss_server_port(config)
            
            if not server or not port:
                return None
            
            # دریافت کشور
            country = self._get_country_code(server)
            
            return {
                'protocol': protocol,
                'server': server,
                'port': port,
                'country': country,
                'original': config
            }
            
        except Exception as e:
            logger.debug(f"Could not extract info from config: {e}")
            return None
    
    def _extract_ss_server_port(self, ss_config: str) -> Tuple[Optional[str], Optional[int]]:
        """استخراج server و port از Shadowsocks"""
        try:
            import base64
            config = ss_config[5:]  # حذف ss://
            main_part = config.split('#')[0].split('?')[0]
            
            if '@' in main_part:
                parts = main_part.rsplit('@', 1)
                server_part = parts[1]
                
                if ':' in server_part:
                    address, port_str = server_part.rsplit(':', 1)
                    return address.strip(), int(port_str)
        except:
            pass
        return None, None
    
    @lru_cache(maxsize=1000)
    def _get_country_code(self, server: str) -> str:
        """
        دریافت کد کشور از IP/domain
        
        Returns:
            کد 2 حرفی کشور (مثل US, DE) یا "Unknown"
        """
        # چک cache
        if not self.settings.USE_GEOIP_CACHE:
            return self._fetch_country_code(server)
        
        if server in self.geoip_cache:
            return self.geoip_cache[server]
        
        country = self._fetch_country_code(server)
        self.geoip_cache[server] = country
        return country
    
    def _fetch_country_code(self, server: str) -> str:
        """دریافت کد کشور از API"""
        try:
            # استفاده از سرویس GeoIP
            service = self.settings.GEOIP_SERVICE
            
            if service == "ip-api.com":
                url = f"http://ip-api.com/json/{server}?fields=countryCode"
                timeout = 3
            elif service == "ipapi.co":
                url = f"https://ipapi.co/{server}/country/"
                timeout = 3
            else:
                return "Unknown"
            
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                if service == "ip-api.com":
                    data = response.json()
                    return data.get('countryCode', 'Unknown')
                else:
                    return response.text.strip()
            
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {server}: {e}")
        
        return "Unknown"
    
    def match_wildcard(self, pattern: str, text: str) -> bool:
        """
        مچ کردن pattern با wildcard
        
        Examples:
            *.cloudflare.com matches cdn.cloudflare.com
            192.168.* matches 192.168.1.1
            cdn.* matches cdn.example.com
        """
        if not self.settings.ENABLE_WILDCARD or '*' not in pattern:
            return pattern == text
        
        # تبدیل wildcard به regex
        regex_pattern = pattern.replace('.', r'\.')
        regex_pattern = regex_pattern.replace('*', '.*')
        regex_pattern = f'^{regex_pattern}$'
        
        return bool(re.match(regex_pattern, text, re.IGNORECASE))
    
    def check_filter(self, config_info: Dict, filters: Dict) -> bool:
        """
        چک کردن اینکه کانفیگ با فیلترها مچ میکنه یا نه
        
        Args:
            config_info: اطلاعات کانفیگ
            filters: فیلترهای کانال
        
        Returns:
            True = قبول | False = رد
        """
        filter_mode = self.settings.FILTER_MODE
        results = []
        
        # فیلتر سرور
        if filters.get('servers'):
            servers_filter = filters['servers']
            if servers_filter != ['*'] and servers_filter:
                match = any(
                    self.match_wildcard(pattern, config_info['server'])
                    for pattern in servers_filter
                )
                results.append(match)
        
        # فیلتر کشور
        if filters.get('countries'):
            countries_filter = filters['countries']
            if countries_filter != ['*'] and countries_filter:
                match = config_info['country'] in countries_filter
                results.append(match)
        
        # فیلتر پروتکل
        if filters.get('protocols'):
            protocols_filter = filters['protocols']
            if protocols_filter != ['*'] and protocols_filter:
                match = config_info['protocol'] in protocols_filter
                results.append(match)
        
        # فیلتر پورت
        if filters.get('ports'):
            ports_filter = filters['ports']
            if ports_filter != ['*'] and ports_filter:
                match = config_info['port'] in ports_filter
                results.append(match)
        
        # اگه هیچ فیلتری نبود، قبول
        if not results:
            return True
        
        # ترکیب نتایج
        if filter_mode == "AND":
            return all(results)
        else:  # OR
            return any(results)
    
    def check_blacklist(self, config_info: Dict) -> bool:
        """
        چک کردن blacklist
        
        Returns:
            True = در blacklist هست (باید رد بشه)
            False = در blacklist نیست (OK)
        """
        # چک server
        for pattern in self.settings.BLACKLIST_SERVERS:
            if self.match_wildcard(pattern, config_info['server']):
                return True
        
        # چک country
        if config_info['country'] in self.settings.BLACKLIST_COUNTRIES:
            return True
        
        # چک protocol
        if config_info['protocol'] in self.settings.BLACKLIST_PROTOCOLS:
            return True
        
        # چک port
        if config_info['port'] in self.settings.BLACKLIST_PORTS:
            return True
        
        return False
    
    def check_whitelist(self, config_info: Dict) -> bool:
        """
        چک کردن whitelist
        
        Returns:
            True = قبول
            False = رد
        """
        if not self.settings.USE_WHITELIST:
            return True
        
        # باید حداقل یکی از شرایط برقرار باشه
        
        # چک server
        if self.settings.WHITELIST_SERVERS:
            if not any(self.match_wildcard(p, config_info['server']) 
                      for p in self.settings.WHITELIST_SERVERS):
                return False
        
        # چک country
        if self.settings.WHITELIST_COUNTRIES:
            if config_info['country'] not in self.settings.WHITELIST_COUNTRIES:
                return False
        
        # چک protocol
        if self.settings.WHITELIST_PROTOCOLS:
            if config_info['protocol'] not in self.settings.WHITELIST_PROTOCOLS:
                return False
        
        # چک port
        if self.settings.WHITELIST_PORTS:
            if config_info['port'] not in self.settings.WHITELIST_PORTS:
                return False
        
        return True
    
    def should_accept_config(self, config: str, channel_filters: Dict) -> bool:
        """
        تصمیم نهایی: آیا این کانفیگ قبوله؟
        
        Args:
            config: رشته کانفیگ
            channel_filters: فیلترهای کانال
        
        Returns:
            True = قبول | False = رد
        """
        if not self.settings.ENABLE_FILTERING:
            return True
        
        # استخراج اطلاعات
        config_info = self.extract_config_info(config)
        if not config_info:
            return False
        
        # 1. چک whitelist (اگه فعال باشه)
        if not self.check_whitelist(config_info):
            if self.settings.LOG_FILTERED_CONFIGS:
                logger.debug(f"❌ Rejected by whitelist: {config_info['server']}")
            return False
        
        # 2. چک blacklist
        if self.check_blacklist(config_info):
            if self.settings.LOG_FILTERED_CONFIGS:
                logger.debug(f"❌ Rejected by blacklist: {config_info['server']}")
            return False
        
        # 3. چک فیلترهای کانال
        if not self.check_filter(config_info, channel_filters):
            if self.settings.LOG_FILTERED_CONFIGS:
                logger.debug(f"❌ Rejected by channel filters: {config_info['server']}")
            return False
        
        # قبول!
        return True
    
    def filter_configs(self, configs: List[str], channel_filters: Dict) -> List[str]:
        """
        فیلتر کردن لیست کانفیگ‌ها
        
        Args:
            configs: لیست کانفیگ‌ها
            channel_filters: فیلترهای کانال
        
        Returns:
            لیست کانفیگ‌های فیلتر شده
        """
        if not self.settings.ENABLE_FILTERING:
            return configs
        
        filtered = []
        total = len(configs)
        
        for config in configs:
            if self.should_accept_config(config, channel_filters):
                filtered.append(config)
        
        accepted = len(filtered)
        rejected = total - accepted
        
        logger.info(f"📊 Filtering: {accepted} accepted, {rejected} rejected from {total} total")
        
        return filtered


# ==============================================================================
# 🧪 تست
# ==============================================================================

def test_filter():
    """تست سیستم فیلترینگ"""
    
    # Import settings
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    
    try:
        import user_settings
    except ImportError:
        print("❌ user_settings.py not found!")
        return
    
    # ایجاد فیلتر
    filter_system = ConfigFilter(user_settings)
    
    # تست با کانفیگ‌های مختلف
    test_configs = [
        "vless://uuid@example.com:443?security=tls#Test1",
        "vmess://base64data@192.168.1.1:8080#Test2",
        "trojan://pass@cdn.cloudflare.com:443#Test3",
        "ss://base64@1.1.1.1:443#Test4",
    ]
    
    test_filters = {
        "servers": ["*.cloudflare.com"],
        "countries": ["*"],
        "protocols": ["*"],
        "ports": [443],
    }
    
    print("="*70)
    print("🧪 Config Filter Test")
    print("="*70)
    
    for config in test_configs:
        result = filter_system.should_accept_config(config, test_filters)
        status = "✅ ACCEPTED" if result else "❌ REJECTED"
        print(f"\n{status}")
        print(f"Config: {config[:60]}...")
        
        info = filter_system.extract_config_info(config)
        if info:
            print(f"  Server: {info['server']}")
            print(f"  Port: {info['port']}")
            print(f"  Protocol: {info['protocol']}")
            print(f"  Country: {info['country']}")


if __name__ == '__main__':
    test_filter()
