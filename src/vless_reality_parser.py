"""
پارسر کامل VLESS با پشتیبانی کامل Reality
نسخه استاندارد - 2025
"""

import json
import base64
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional, List
import re


class VLESSParser:
    """پارسر حرفه‌ای VLESS با پشتیبانی کامل Reality"""
    
    # Transport types معتبر
    VALID_TRANSPORTS = ['tcp', 'kcp', 'ws', 'http', 'quic', 'grpc', 'httpupgrade']
    
    # Security types معتبر
    VALID_SECURITIES = ['none', 'tls', 'reality']
    
    # Flow types معتبر (برای XTLS)
    VALID_FLOWS = ['', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443']
    
    @staticmethod
    def normalize_query_params(query_string: str) -> str:
        """تمیز کردن query string از مشکلات encoding تلگرام"""
        # مشکل &amp; از تلگرام
        query_string = query_string.replace('&amp;', '&')
        query_string = query_string.replace('&amp;amp;', '&')
        return query_string
    
    @staticmethod
    def parse_vless_url(vless_url: str) -> Optional[Dict]:
        """
        پارس کامل URL های VLESS
        
        فرمت استاندارد:
        vless://[uuid]@[server]:[port]?[params]#[name]
        
        پارامترهای مهم برای Reality:
        - security=reality
        - pbk=public_key (Reality public key)
        - fp=fingerprint (chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized)
        - sni=server_name
        - sid=short_id (اختیاری)
        - spx=spider_x (اختیاری - path for spider)
        - type=transport (tcp, grpc, ws, etc.)
        - flow=xtls-rprx-vision (برای Reality معمولاً vision)
        """
        
        try:
            if not vless_url.startswith('vless://'):
                return None
            
            # پارس URL
            parsed = urlparse(vless_url)
            
            if not parsed.hostname or not parsed.port:
                print(f"❌ Missing hostname or port: {vless_url[:50]}...")
                return None
            
            # استخراج UUID
            uuid_str = parsed.username
            if not uuid_str or len(uuid_str) != 36:
                print(f"❌ Invalid UUID: {uuid_str}")
                return None
            
            # پارس query parameters
            query_normalized = VLESSParser.normalize_query_params(parsed.query)
            params = parse_qs(query_normalized)
            
            # تابع کمکی برای گرفتن اولین مقدار
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return unquote(values[0]) if values else default
            
            # استخراج پارامترهای اصلی
            security = get_param('security', 'none').lower()
            transport_type = get_param('type', 'tcp').lower()
            flow = get_param('flow', '')
            
            # Validation
            if security not in VLESSParser.VALID_SECURITIES:
                print(f"⚠️  Invalid security: {security}, defaulting to 'none'")
                security = 'none'
            
            if transport_type not in VLESSParser.VALID_TRANSPORTS:
                print(f"⚠️  Invalid transport: {transport_type}, defaulting to 'tcp'")
                transport_type = 'tcp'
            
            # ساخت دیکشنری پایه
            config = {
                'uuid': uuid_str,
                'server': parsed.hostname,
                'port': parsed.port,
                'security': security,
                'transport_type': transport_type,
                'flow': flow if flow in VLESSParser.VALID_FLOWS else '',
            }
            
            # پردازش TLS/Reality
            if security == 'reality':
                config['reality'] = VLESSParser._parse_reality_params(params, parsed.hostname)
            elif security == 'tls':
                config['tls'] = VLESSParser._parse_tls_params(params, parsed.hostname)
            
            # پردازش Transport
            config['transport'] = VLESSParser._parse_transport(transport_type, params)
            
            # اسم کانفیگ (fragment)
            config['tag'] = unquote(parsed.fragment) if parsed.fragment else f"VLESS-{uuid_str[:8]}"
            
            return config
            
        except Exception as e:
            print(f"❌ Parse error for {vless_url[:50]}...\n   Error: {e}")
            return None
    
    @staticmethod
    def _parse_reality_params(params: Dict, default_sni: str) -> Dict:
        """استخراج پارامترهای Reality"""
        
        def get_param(key: str, default: str = '') -> str:
            values = params.get(key, [default])
            return unquote(values[0]) if values else default
        
        reality_config = {
            'enabled': True,
            'public_key': get_param('pbk'),  # الزامی
            'short_id': get_param('sid', ''),  # اختیاری
        }
        
        # Server Name
        sni = get_param('sni', get_param('peer', default_sni))
        reality_config['server_name'] = sni
        
        # Fingerprint
        fp = get_param('fp', 'chrome')
        valid_fps = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized']
        if fp not in valid_fps:
            print(f"⚠️  Invalid fingerprint: {fp}, using 'chrome'")
            fp = 'chrome'
        reality_config['fingerprint'] = fp
        
        # Spider X (path)
        spx = get_param('spx', '')
        if spx:
            reality_config['spider_x'] = spx
        
        # Validation
        if not reality_config['public_key']:
            print("⚠️  Reality config missing public_key (pbk)!")
        
        return reality_config
    
    @staticmethod
    def _parse_tls_params(params: Dict, default_sni: str) -> Dict:
        """استخراج پارامترهای TLS معمولی"""
        
        def get_param(key: str, default: str = '') -> str:
            values = params.get(key, [default])
            return unquote(values[0]) if values else default
        
        sni = get_param('sni', get_param('peer', default_sni))
        alpn_str = get_param('alpn', 'h2,http/1.1')
        alpn = [a.strip() for a in alpn_str.split(',') if a.strip()]
        
        insecure_val = get_param('allowInsecure', get_param('insecure', '0'))
        insecure = insecure_val in ('1', 'true', 'yes')
        
        return {
            'enabled': True,
            'server_name': sni,
            'alpn': alpn,
            'insecure': insecure,
        }
    
    @staticmethod
    def _parse_transport(transport_type: str, params: Dict) -> Optional[Dict]:
        """پردازش Transport layer"""
        
        def get_param(key: str, default: str = '') -> str:
            values = params.get(key, [default])
            return unquote(values[0]) if values else default
        
        if transport_type == 'tcp':
            header_type = get_param('headerType', 'none')
            if header_type == 'http':
                return {
                    'type': 'http',
                    'host': get_param('host', '').split(','),
                    'path': get_param('path', '/'),
                }
            return None  # TCP ساده نیاز به transport نداره
        
        elif transport_type == 'ws':
            return {
                'type': 'ws',
                'path': get_param('path', '/'),
                'headers': {'Host': get_param('host', '')} if get_param('host') else {},
                'max_early_data': int(get_param('ed', '0')),
                'early_data_header_name': get_param('eh', 'Sec-WebSocket-Protocol') if get_param('ed') else None,
            }
        
        elif transport_type == 'grpc':
            return {
                'type': 'grpc',
                'service_name': get_param('serviceName', get_param('path', '')),
                'idle_timeout': '15s',
                'ping_timeout': '15s',
            }
        
        elif transport_type == 'httpupgrade':
            return {
                'type': 'httpupgrade',
                'host': get_param('host', ''),
                'path': get_param('path', '/'),
            }
        
        elif transport_type == 'quic':
            return {
                'type': 'quic',
                'security': get_param('quicSecurity', 'none'),
                'key': get_param('key', ''),
            }
        
        elif transport_type == 'kcp':
            return {
                'type': 'kcp',
                'header': {'type': get_param('headerType', 'none')},
                'seed': get_param('seed', ''),
            }
        
        elif transport_type == 'http':
            return {
                'type': 'http',
                'host': get_param('host', '').split(','),
                'path': get_param('path', '/'),
            }
        
        return None


class VLESSToSingBox:
    """تبدیل VLESS به فرمت Sing-Box"""
    
    @staticmethod
    def convert(vless_config: Dict) -> Dict:
        """
        تبدیل دیکشنری VLESS به فرمت Sing-Box
        """
        
        outbound = {
            'type': 'vless',
            'tag': vless_config['tag'],
            'server': vless_config['server'],
            'server_port': vless_config['port'],
            'uuid': vless_config['uuid'],
        }
        
        # Flow (برای XTLS/Reality)
        if vless_config.get('flow'):
            outbound['flow'] = vless_config['flow']
        
        # Security Layer
        if vless_config['security'] == 'reality':
            reality = vless_config['reality']
            outbound['tls'] = {
                'enabled': True,
                'server_name': reality['server_name'],
                'insecure': False,
                'utls': {
                    'enabled': True,
                    'fingerprint': reality['fingerprint'],
                },
                'reality': {
                    'enabled': True,
                    'public_key': reality['public_key'],
                    'short_id': reality.get('short_id', ''),
                }
            }
            # Spider X (اگه داشته باشه)
            if reality.get('spider_x'):
                outbound['tls']['reality']['spider_x'] = reality['spider_x']
        
        elif vless_config['security'] == 'tls':
            tls = vless_config['tls']
            outbound['tls'] = {
                'enabled': True,
                'server_name': tls['server_name'],
                'alpn': tls.get('alpn', ['h2', 'http/1.1']),
                'insecure': tls.get('insecure', False),
            }
        
        # Transport Layer
        if vless_config.get('transport'):
            transport = vless_config['transport']
            # پاک‌سازی None values
            transport_clean = {k: v for k, v in transport.items() if v is not None}
            if transport_clean:
                outbound['transport'] = transport_clean
        
        return outbound


# ============== تست و استفاده ==============

def test_vless_parser():
    """تست با نمونه‌های واقعی"""
    
    test_cases = [
        # Reality با همه پارامترها
        "vless://4d0f186d-783b-493f-95b1-b5d7a2d6b9e3@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=google.com&fp=chrome&pbk=SbVKOEMHLVEuMdNXZic&sid=6ba85179e30d4fc2&spx=%2F&type=tcp#Reality-Full",
        
        # Reality ساده
        "vless://uuid@1.2.3.4:443?security=reality&pbk=publickey123&sni=yahoo.com&fp=firefox&type=tcp&flow=xtls-rprx-vision#Reality-Simple",
        
        # TLS با WebSocket
        "vless://uuid@domain.com:443?security=tls&sni=domain.com&type=ws&path=/vless&host=domain.com#TLS-WS",
        
        # gRPC
        "vless://uuid@5.6.7.8:443?security=tls&type=grpc&serviceName=VLESSService&sni=example.org#VLESS-gRPC",
    ]
    
    print("=" * 70)
    print("تست پارسر VLESS")
    print("=" * 70)
    
    for i, url in enumerate(test_cases, 1):
        print(f"\n📝 Test Case {i}:")
        print(f"URL: {url[:80]}...")
        
        parsed = VLESSParser.parse_vless_url(url)
        if parsed:
            print("✅ Parse successful!")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
            
            # تبدیل به Sing-Box
            print("\n🔄 Converting to Sing-Box format...")
            singbox = VLESSToSingBox.convert(parsed)
            print(json.dumps(singbox, indent=2, ensure_ascii=False))
        else:
            print("❌ Parse failed!")
        
        print("-" * 70)


if __name__ == '__main__':
    test_vless_parser()
