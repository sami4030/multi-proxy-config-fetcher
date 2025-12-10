"""
تبدیل کننده کامل پروکسی به Sing-Box
با پشتیبانی کامل Reality و همه Transport ها
نسخه 2.0 - 2025
"""

import json
import base64
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional, Tuple
import requests
from functools import lru_cache
import time
from collections import deque


# ============== Rate Limiter ==============
class RateLimiter:
    """محدود کننده تعداد درخواست"""
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            now = time.time()
            # حذف تماس‌های قدیمی
            while self.calls and self.calls[0] < now - self.period:
                self.calls.popleft()
            
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            self.calls.append(time.time())
            return func(*args, **kwargs)
        return wrapper


@RateLimiter(max_calls=40, period=60)
@lru_cache(maxsize=10000)
def get_country_info(ip: str) -> Tuple[str, str]:
    """دریافت اطلاعات کشور با rate limiting"""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                code = data["countryCode"].lower()
                flag = ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())
                return flag, data["country"]
    except:
        pass
    return "🌍", "Unknown"


# ============== VLESS Parser (با Reality) ==============
class VLESSParser:
    """پارسر پیشرفته VLESS"""
    
    VALID_TRANSPORTS = ['tcp', 'kcp', 'ws', 'http', 'quic', 'grpc', 'httpupgrade']
    VALID_SECURITIES = ['none', 'tls', 'reality']
    
    @staticmethod
    def parse(vless_url: str) -> Optional[Dict]:
        try:
            if not vless_url.startswith('vless://'):
                return None
            
            parsed = urlparse(vless_url)
            if not parsed.hostname or not parsed.port:
                return None
            
            # نرمال‌سازی query
            query = parsed.query.replace('&amp;', '&').replace('&amp;amp;', '&')
            params = parse_qs(query)
            
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return unquote(values[0]) if values else default
            
            security = get_param('security', 'none').lower()
            transport_type = get_param('type', 'tcp').lower()
            flow = get_param('flow', '')
            
            config = {
                'uuid': parsed.username,
                'server': parsed.hostname,
                'port': parsed.port,
                'security': security,
                'transport_type': transport_type,
                'flow': flow,
                'tag': unquote(parsed.fragment) if parsed.fragment else f"VL-{parsed.username[:8]}"
            }
            
            # Reality
            if security == 'reality':
                config['reality'] = {
                    'enabled': True,
                    'public_key': get_param('pbk'),
                    'short_id': get_param('sid', ''),
                    'server_name': get_param('sni', get_param('peer', parsed.hostname)),
                    'fingerprint': get_param('fp', 'chrome'),
                }
                if get_param('spx'):
                    config['reality']['spider_x'] = get_param('spx')
            
            # TLS
            elif security == 'tls':
                sni = get_param('sni', get_param('peer', parsed.hostname))
                alpn_str = get_param('alpn', 'h2,http/1.1')
                config['tls'] = {
                    'enabled': True,
                    'server_name': sni,
                    'alpn': [a.strip() for a in alpn_str.split(',')],
                    'insecure': get_param('allowInsecure', get_param('insecure', '0')) in ('1', 'true'),
                }
            
            # Transport
            if transport_type == 'ws':
                config['transport'] = {
                    'type': 'ws',
                    'path': get_param('path', '/'),
                    'headers': {'Host': get_param('host')} if get_param('host') else {},
                }
            elif transport_type == 'grpc':
                config['transport'] = {
                    'type': 'grpc',
                    'service_name': get_param('serviceName', get_param('path', '')),
                }
            elif transport_type == 'httpupgrade':
                config['transport'] = {
                    'type': 'httpupgrade',
                    'host': get_param('host', ''),
                    'path': get_param('path', '/'),
                }
            elif transport_type == 'http':
                config['transport'] = {
                    'type': 'http',
                    'host': get_param('host', '').split(','),
                    'path': get_param('path', '/'),
                }
            
            return config
            
        except Exception as e:
            print(f"VLESS parse error: {e}")
            return None


class ConfigToSingbox:
    """مبدل اصلی"""
    
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'
    
    def decode_vmess(self, config: str) -> Optional[Dict]:
        """دیکد VMess"""
        try:
            encoded = config[8:]
            padding = '=' * ((4 - len(encoded) % 4) % 4)
            decoded_bytes = base64.b64decode(encoded + padding, validate=True)
            return json.loads(decoded_bytes.decode('utf-8'))
        except:
            return None
    
    def parse_trojan(self, config: str) -> Optional[Dict]:
        """پارس Trojan"""
        try:
            url = urlparse(config)
            if url.scheme != 'trojan' or not url.hostname:
                return None
            params = parse_qs(url.query)
            
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return values[0] if values else default
            
            return {
                'password': url.username,
                'address': url.hostname,
                'port': url.port or 443,
                'sni': get_param('sni', url.hostname),
                'type': get_param('type', 'tcp'),
                'path': get_param('path', ''),
                'alpn': get_param('alpn', 'h2,http/1.1').split(',') if get_param('alpn') else ['h2', 'http/1.1'],
            }
        except:
            return None
    
    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        """پارس Hysteria2 با obfs کامل"""
        try:
            config = config.strip()
            if config.lower().startswith('hy2://'):
                config = config.replace('hy2://', 'hysteria2://', 1)
            
            url = urlparse(config)
            if url.scheme != 'hysteria2' or not url.hostname or not url.port:
                return None
            
            query_normalized = url.query.replace('&amp;', '&').replace('&amp;amp;', '&')
            params = parse_qs(query_normalized)
            
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return values[0] if values else default
            
            main_password = get_param('password') or url.username or ''
            obfs_password = get_param('obfs-password')
            obfs_type = get_param('obfs')
            
            if not main_password and not obfs_password:
                return None
            
            sni = get_param('sni') or get_param('peer') or url.hostname
            
            result = {
                "address": url.hostname,
                "port": url.port,
                "password": main_password or obfs_password,
                "sni": sni,
            }
            
            if obfs_type and obfs_password:
                result["obfs"] = {
                    "type": obfs_type,
                    "password": obfs_password
                }
            
            insecure_val = get_param('insecure', '0')
            result["tls"] = {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure_val in ('1', 'true', 'yes')
            }
            
            return result
            
        except Exception as e:
            print(f"Hysteria2 parse error: {e}")
            return None
    
    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        """پارس Shadowsocks"""
        try:
            config = config[5:]  # حذف ss://
            if '@' not in config:
                return None
            
            # فرمت جدید 2022
            if config.count('@') >= 2:
                encoded, server_part = config.rsplit('@', 1)
                method_pass = base64.b64decode(encoded + '==').decode('utf-8')
                method, password = method_pass.split(':', 1)
                server = server_part.split('/')[0].split('?')[0].split('#')[0]
                address, port_str = server.rsplit(':', 1)
            else:
                # فرمت قدیمی
                encoded_all = config.split('#')[0]
                method_pass_b64, server = encoded_all.split('@')
                method_pass = base64.b64decode(method_pass_b64 + '==').decode('utf-8')
                method, password = method_pass.split(':', 1)
                address, port_str = server.split(':', 1)
            
            return {
                'method': method,
                'password': password,
                'address': address,
                'port': int(port_str),
            }
        except:
            return None
    
    def parse_tuic(self, config: str) -> Optional[Dict]:
        """پارس TUIC"""
        try:
            if not config.startswith('tuic://'):
                return None
            
            parsed = urlparse(config)
            if not parsed.hostname or not parsed.port or not parsed.username:
                return None
            
            params = parse_qs(parsed.query)
            
            def get_param(key: str, default: str = '') -> str:
                values = params.get(key, [default])
                return unquote(values[0]) if values else default
            
            cc = get_param('congestion_control', 'bbr').lower()
            if cc not in ['bbr', 'cubic', 'new_reno']:
                cc = 'bbr'
            
            udp_mode = get_param('udp_relay_mode', 'native').lower()
            if udp_mode not in ['native', 'quic']:
                udp_mode = 'native'
            
            alpn_str = get_param('alpn', 'h3')
            alpn = [a.strip() for a in alpn_str.split(',') if a.strip()]
            
            return {
                'uuid': parsed.username,
                'password': parsed.password or '',
                'address': parsed.hostname,
                'port': parsed.port,
                'congestion_control': cc,
                'udp_relay_mode': udp_mode,
                'alpn': alpn,
                'sni': get_param('sni', parsed.hostname),
                'disable_sni': get_param('disable_sni', '0') in ('1', 'true'),
                'insecure': get_param('allow_insecure', get_param('allowInsecure', '0')) in ('1', 'true'),
            }
        except:
            return None
    
    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        """تبدیل به Sing-Box"""
        config = config.strip()
        if not config or config.startswith('//'):
            return None
        
        lower = config.lower()
        
        try:
            # ============== VLESS (با Reality کامل) ==============
            if lower.startswith('vless://'):
                d = VLESSParser.parse(config)
                if not d:
                    return None
                
                flag, country = get_country_info(d['server'])
                
                outbound = {
                    "type": "vless",
                    "tag": f"{flag} {d['tag']} ({country})",
                    "server": d['server'],
                    "server_port": d['port'],
                    "uuid": d['uuid'],
                }
                
                # Flow
                if d.get('flow'):
                    outbound['flow'] = d['flow']
                
                # Reality
                if d.get('reality'):
                    r = d['reality']
                    outbound['tls'] = {
                        'enabled': True,
                        'server_name': r['server_name'],
                        'insecure': False,
                        'utls': {
                            'enabled': True,
                            'fingerprint': r['fingerprint'],
                        },
                        'reality': {
                            'enabled': True,
                            'public_key': r['public_key'],
                            'short_id': r.get('short_id', ''),
                        }
                    }
                    if r.get('spider_x'):
                        outbound['tls']['reality']['spider_x'] = r['spider_x']
                
                # TLS
                elif d.get('tls'):
                    t = d['tls']
                    outbound['tls'] = {
                        'enabled': True,
                        'server_name': t['server_name'],
                        'alpn': t.get('alpn', ['h2', 'http/1.1']),
                        'insecure': t.get('insecure', False),
                    }
                
                # Transport
                if d.get('transport'):
                    transport_clean = {k: v for k, v in d['transport'].items() if v is not None and v != {} and v != []}
                    if transport_clean:
                        outbound['transport'] = transport_clean
                
                return outbound
            
            # ============== VMess ==============
            elif lower.startswith('vmess://'):
                data = self.decode_vmess(config)
                if not data or not data.get('add') or not data.get('id'):
                    return None
                
                addr = data['add']
                port = int(data.get('port', 443))
                flag, country = get_country_info(addr)
                
                transport = {}
                net = data.get('net', 'tcp')
                if net in ['ws', 'http', 'h2']:
                    transport['type'] = 'ws' if net != 'h2' else 'http'
                    if data.get('path'):
                        transport['path'] = data['path']
                    if data.get('host'):
                        transport['headers'] = {'Host': data['host']}
                
                tls_enabled = data.get('tls') == 'tls'
                return {
                    "type": "vmess",
                    "tag": f"{flag} VM-{str(uuid.uuid4())[:4]} ({country})",
                    "server": addr,
                    "server_port": port,
                    "uuid": data['id'],
                    "security": data.get('scy', 'auto'),
                    "alter_id": int(data.get('aid', 0)),
                    "transport": transport if transport else None,
                    "tls": {
                        "enabled": tls_enabled,
                        "server_name": data.get('sni') or data.get('host') or addr,
                        "insecure": not tls_enabled
                    } if tls_enabled or transport else None
                }
            
            # ============== Trojan ==============
            elif lower.startswith('trojan://'):
                d = self.parse_trojan(config)
                if not d:
                    return None
                flag, country = get_country_info(d['address'])
                
                transport = {}
                if d['type'] != 'tcp':
                    transport = {"type": d['type'], "path": d.get('path')}
                
                return {
                    "type": "trojan",
                    "tag": f"{flag} TR-{str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "password": d['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": d['sni'],
                        "alpn": d['alpn'],
                        "insecure": False
                    },
                    "transport": transport if transport else None
                }
            
            # ============== Hysteria2 ==============
            elif lower.startswith(('hysteria2://', 'hy2://')):
                d = self.parse_hysteria2(config)
                if not d:
                    return None
                flag, country = get_country_info(d['address'])
                
                outbound = {
                    "type": "hysteria2",
                    "tag": f"{flag} Hy2-{str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "password": d['password'],
                    "tls": d['tls']
                }
                if d.get('obfs'):
                    outbound["obfs"] = d['obfs']
                return outbound
            
            # ============== Shadowsocks ==============
            elif lower.startswith('ss://'):
                d = self.parse_shadowsocks(config)
                if not d:
                    return None
                flag, country = get_country_info(d['address'])
                return {
                    "type": "shadowsocks",
                    "tag": f"{flag} SS-{str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "method": d['method'],
                    "password": d['password']
                }
            
            # ============== TUIC ==============
            elif lower.startswith('tuic://'):
                d = self.parse_tuic(config)
                if not d:
                    return None
                flag, country = get_country_info(d['address'])
                
                outbound = {
                    "type": "tuic",
                    "tag": f"{flag} TUIC-{str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "uuid": d['uuid'],
                    "congestion_control": d['congestion_control'],
                    "udp_relay_mode": d['udp_relay_mode'],
                    "tls": {
                        "enabled": True,
                        "server_name": d['sni'],
                        "alpn": d['alpn'],
                        "insecure": d['insecure'],
                    }
                }
                
                if d.get('password'):
                    outbound['password'] = d['password']
                
                if d.get('disable_sni'):
                    outbound['tls']['disable_sni'] = True
                
                return outbound
        
        except Exception as e:
            print(f"❌ Conversion failed: {config[:60]}... → {e}")
        
        return None
    
    def process_configs(self):
        """پردازش فایل و تبدیل"""
        try:
            with open('configs/proxy_configs.txt', 'r', encoding='utf-8') as f:
                lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith('//')]
            
            outbounds = []
            valid_tags = []
            
            print(f"📥 Processing {len(lines)} configs...")
            
            for cfg in lines:
                conv = self.convert_to_singbox(cfg)
                if conv:
                    outbounds.append(conv)
                    valid_tags.append(conv['tag'])
            
            if not outbounds:
                print("❌ No valid configs found!")
                return
            
            print(f"✅ Successfully converted {len(outbounds)} configs")
            
            # آمار پروتکل‌ها
            protocol_stats = {}
            for out in outbounds:
                ptype = out['type']
                protocol_stats[ptype] = protocol_stats.get(ptype, 0) + 1
            
            print("\n📊 Protocol Statistics:")
            for proto, count in sorted(protocol_stats.items()):
                print(f"   {proto}: {count}")
            
            # ساخت فایل Sing-Box
            config = {
                "log": {"level": "warn"},
                "dns": {
                    "servers": [
                        {"tag": "proxy-dns", "address": "tls://1.1.1.1", "detour": "proxy"},
                        {"tag": "local-dns", "address": "local", "detour": "direct"},
                        {"tag": "block", "address": "rcode://refused"}
                    ],
                    "rules": [
                        {"outbound": "any", "server": "local-dns"},
                        {"clash_mode": "Global", "server": "proxy-dns"}
                    ],
                    "final": "proxy-dns",
                    "strategy": "prefer_ipv4"
                },
                "inbounds": [
                    {
                        "type": "tun",
                        "inet4_address": "172.19.0.1/30",
                        "inet6_address": "fdfe:dcba:9876::1/126",
                        "mtu": 9000,
                        "auto_route": True,
                        "strict_route": True,
                        "sniff": True,
                        "stack": "system"
                    },
                    {
                        "type": "mixed",
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
                        "sniff": True
                    }
                ],
                "outbounds": [
                    {"type": "selector", "tag": "Proxy", "outbounds": ["Auto"] + valid_tags + ["Direct"]},
                    {
                        "type": "urltest",
                        "tag": "Auto",
                        "outbounds": valid_tags,
                        "url": "http://www.gstatic.com/generate_204",
                        "interval": "5m",
                        "tolerance": 100
                    },
                    {"type": "direct", "tag": "Direct"},
                    {"type": "block", "tag": "block"}
                ] + outbounds,
                "route": {
                    "auto_detect_interface": True,
                    "final": "Proxy"
                },
                "experimental": {
                    "cache_file": {"enabled": True}
                }
            }
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            print(f"\n✅ Sing-Box config saved to: {self.output_file}")
        
        except FileNotFoundError:
            print("❌ File 'configs/proxy_configs.txt' not found!")
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == '__main__':
    ConfigToSingbox().process_configs()
