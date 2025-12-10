"""
پارسر کامل TUIC برای Sing-Box
TUIC v4 & v5 Support
"""

import json
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional


class TUICParser:
    """
    پارسر TUIC (v4 & v5)
    
    فرمت استاندارد:
    tuic://[uuid]:[password]@[server]:[port]?[params]#[name]
    
    پارامترهای مهم:
    - congestion_control: bbr, cubic, new_reno
    - udp_relay_mode: native, quic
    - alpn: h3 (معمولاً برای TUIC)
    - sni: server name indication
    - disable_sni: 0 یا 1
    - allow_insecure: 0 یا 1
    """
    
    # Congestion control algorithms معتبر
    VALID_CC = ['bbr', 'cubic', 'new_reno']
    
    # UDP relay modes معتبر
    VALID_UDP_MODE = ['native', 'quic']
    
    @staticmethod
    def parse(tuic_url: str) -> Optional[Dict]:
        """پارس URL های TUIC"""
        try:
            if not tuic_url.startswith('tuic://'):
                return None
            
            parsed = urlparse(tuic_url)
            
            if not parsed.hostname or not parsed.port:
                print(f"❌ TUIC: Missing hostname or port")
                return None
            
            # UUID و Password
            uuid_str = parsed.username
            password = parsed.password
            
            if not uuid_str:
                print(f"❌ TUIC: Missing UUID")
                return None
            
            # پارس query parameters
            params = parse_qs(parsed.query)
            
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return unquote(values[0]) if values else default
            
            # Congestion Control
            cc = get_param('congestion_control', 'bbr').lower()
            if cc not in TUICParser.VALID_CC:
                print(f"⚠️  Invalid congestion_control: {cc}, using bbr")
                cc = 'bbr'
            
            # UDP Relay Mode
            udp_mode = get_param('udp_relay_mode', 'native').lower()
            if udp_mode not in TUICParser.VALID_UDP_MODE:
                print(f"⚠️  Invalid udp_relay_mode: {udp_mode}, using native")
                udp_mode = 'native'
            
            # ALPN
            alpn_str = get_param('alpn', 'h3')
            alpn = [a.strip() for a in alpn_str.split(',') if a.strip()]
            
            # SNI
            sni = get_param('sni', parsed.hostname)
            disable_sni = get_param('disable_sni', '0') in ('1', 'true')
            
            # Security
            allow_insecure = get_param('allow_insecure', get_param('allowInsecure', '0'))
            insecure = allow_insecure in ('1', 'true')
            
            config = {
                'uuid': uuid_str,
                'password': password or '',
                'server': parsed.hostname,
                'port': parsed.port,
                'congestion_control': cc,
                'udp_relay_mode': udp_mode,
                'alpn': alpn,
                'sni': sni,
                'disable_sni': disable_sni,
                'insecure': insecure,
                'tag': unquote(parsed.fragment) if parsed.fragment else f"TUIC-{uuid_str[:8]}"
            }
            
            return config
            
        except Exception as e:
            print(f"❌ TUIC parse error: {e}")
            return None
    
    @staticmethod
    def to_singbox(tuic_config: Dict) -> Dict:
        """تبدیل به فرمت Sing-Box"""
        
        outbound = {
            'type': 'tuic',
            'tag': tuic_config['tag'],
            'server': tuic_config['server'],
            'server_port': tuic_config['port'],
            'uuid': tuic_config['uuid'],
            'congestion_control': tuic_config['congestion_control'],
            'udp_relay_mode': tuic_config['udp_relay_mode'],
        }
        
        # Password (اختیاری)
        if tuic_config.get('password'):
            outbound['password'] = tuic_config['password']
        
        # TLS
        outbound['tls'] = {
            'enabled': True,
            'server_name': tuic_config['sni'],
            'alpn': tuic_config['alpn'],
            'insecure': tuic_config['insecure'],
        }
        
        # Disable SNI
        if tuic_config.get('disable_sni'):
            outbound['tls']['disable_sni'] = True
        
        return outbound


def test_tuic_parser():
    """تست با نمونه‌های مختلف"""
    
    test_cases = [
        # TUIC v5 کامل
        "tuic://00000000-0000-0000-0000-000000000000:password123@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=example.com#TUIC-v5",
        
        # TUIC ساده
        "tuic://uuid-here:pass@1.2.3.4:8443?alpn=h3#Simple-TUIC",
        
        # با cubic congestion control
        "tuic://my-uuid:mypass@server.com:443?congestion_control=cubic&udp_relay_mode=quic&alpn=h3,h2&sni=example.org#TUIC-Cubic",
        
        # با insecure
        "tuic://uuid:pass@192.168.1.1:443?allow_insecure=1&alpn=h3#Insecure-TUIC",
    ]
    
    print("="*70)
    print("🟢 TUIC Parser Test")
    print("="*70)
    
    for i, url in enumerate(test_cases, 1):
        print(f"\n📝 Test Case {i}:")
        print(f"URL: {url}")
        
        parsed = TUICParser.parse(url)
        if parsed:
            print("\n✅ Parse successful!")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
            
            print("\n🔄 Sing-Box format:")
            singbox = TUICParser.to_singbox(parsed)
            print(json.dumps(singbox, indent=2, ensure_ascii=False))
        else:
            print("\n❌ Parse failed!")
        
        print("-"*70)


if __name__ == '__main__':
    test_tuic_parser()
