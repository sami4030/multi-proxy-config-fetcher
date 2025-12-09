# config_to_singbox.py
# نسخه نهایی - به‌روزرسانی ۱۴۰۴/۹/۱۸ (2025)

import json
import base64
import uuid
import socket
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Tuple
import requests
from functools import lru_cache

# کش قوی برای جلوگیری از درخواست تکراری geolocation
@lru_cache(maxsize=10000)
def get_country_info(ip: str) -> Tuple[str, str]:
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
    return "Unknown", "Unknown"


class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    # ==================== VMess ====================
    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config[8:]
            padding = '=' * ((4 - len(encoded) % 4) % 4)
            decoded_bytes = base64.b64decode(encoded + padding, validate=True)
            return json.loads(decoded_bytes.decode('utf-8'))
        except:
            return None

    # ==================== VLESS ====================
    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'vless' or not url.hostname:
                return None
            params = parse_qs(url.query)
            return {
                'uuid': url.username,
                'address': url.hostname,
                'port': url.port or 443,
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [url.hostname])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0],
                'security': params.get('security', ['tls'])[0],
                'insecure': params.get('insecure', ['0'])[0] in ['1', 'true']
            }
        except:
            return None

    # ==================== Trojan ====================
    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'trojan' or not url.hostname:
                return None
            params = parse_qs(url.query)
            return {
                'password': url.username,
                'address': url.hostname,
                'port': url.port or 443,
                'sni': params.get('sni', [url.hostname])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'alpn': params.get('alpn', ['h2,http/1.1'])[0].split(',') if params.get('alpn') else ['h2', 'http/1.1'],
            }
        except:
            return None

    # ==================== Hysteria2 (با obfs کامل) ====================
    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            config = config.strip()
            if config.lower().startswith('hy2://'):
                config = config.replace('hy2://', 'hysteria2://', 1)

            url = urlparse(config)
            if url.scheme != 'hysteria2' or not url.hostname or not url.port:
                return None

            params = parse_qs(url.query)

            # اولویت: obfs-password → password → username
            password = (
                params.get('obfs-password', [''])[0] or
                params.get('password', [''])[0] or
                url.username or
                ''
            )
            if not password:
                return None

            sni = params.get('sni', params.get('peer', [url.hostname]))[0]

            result = {
                "address": url.hostname,
                "port": url.port,
                "password": password,
                "sni": sni,
            }

            # obfs
            obfs_type = params.get('obfs', [''])[0]
            obfs_pass = params.get('obfs-password', [''])[0]
            if obfs_type and obfs_pass:
                result["obfs"] = {"type": obfs_type, "password": obfs_pass}

            # insecure
            insecure = params.get('insecure', ['0'])[0] in ['1', 'true', 'yes']
            result["tls"] = {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure
            }

            return result
        except Exception as e:
            print(f"Hysteria2 parse error: {e}")
            return None

    # ==================== Shadowsocks (قدیمی + 2022) ====================
    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            config = config[5:]  # ss://
            if '@' not in config:
                return None

            if config.count('@') >= 2:
                # فرمت 2022: ss://method:pass@server:port
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

    # ==================== تبدیل اصلی ====================
    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        config = config.strip()
        if not config or config.startswith('//'):
            return None

        lower = config.lower()

        try:
            if lower.startswith('vmess://'):
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
                    "tag": f"{flag} VM {str(uuid.uuid4())[:4]} ({country})",
                    "server": addr,
                    "server_port": port,
                    "uuid": data['id'],
                    "security": data.get('scy', 'auto'),
                    "alter_id": int(data.get('aid', 0)),
                    "transport": transport or None,
                    "tls": {
                        "enabled": tls_enabled,
                        "server_name": data.get('sni') or data.get('host') or addr,
                        "insecure": not tls_enabled
                    } if tls_enabled or transport else None
                }

            elif lower.startswith('vless://'):
                d = self.parse_vless(config)
                if not d: return None
                flag, country = get_country_info(d['address'])
                transport = {}
                if d['type'] == 'ws':
                    transport = {"type": "ws"}
                    if d.get('path'): transport["path"] = d['path']
                    if d.get('host'): transport["headers"] = {"Host": d['host']}

                return {
                    "type": "vless",
                    "tag": f"{flag} VL {str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "uuid": d['uuid'],
                    "flow": d['flow'] if d['flow'] else None,
                    "tls": {
                        "enabled": d['security'] == 'tls',
                        "server_name": d['sni'],
                        "insecure": d['insecure']
                    },
                    "transport": transport or None
                }

            elif lower.startswith(('trojan://')):
                d = self.parse_trojan(config)
                if not d: return None
                flag, country = get_country_info(d['address'])
                transport = {}
                if d['type'] != 'tcp':
                    transport = {"type": d['type'], "path": d.get('path')}

                return {
                    "type": "trojan",
                    "tag": f"{flag} TR {str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "password": d['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": d['sni'],
                        "alpn": d['alpn'],
                        "insecure": False
                    },
                    "transport": transport or None
                }

            elif lower.startswith(('hysteria2://', 'hy2://')):
                d = self.parse_hysteria2(config)
                if not d: return None
                flag, country = get_country_info(d['address'])

                outbound = {
                    "type": "hysteria2",
                    "tag": f"{flag} Hy2 {str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "password": d['password'],
                    "tls": d['tls']
                }
                if d.get('obfs'):
                    outbound["obfs"] = d['obfs']
                return outbound

            elif lower.startswith('ss://'):
                d = self.parse_shadowsocks(config)
                if not d: return None
                flag, country = get_country_info(d['address'])
                return {
                    "type": "shadowsocks",
                    "tag": f"{flag} SS {str(uuid.uuid4())[:4]} ({country})",
                    "server": d['address'],
                    "server_port": d['port'],
                    "method": d['method'],
                    "password": d['password']
                }

        except Exception as e:
            print(f"تبدیل ناموفق: {config[:60]}... → {e}")
        return None

    # ==================== پردازش نهایی ====================
    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r', encoding='utf-8') as f:
                lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith('//')]

            outbounds = []
            valid_tags = []

            for cfg in lines:
                conv = self.convert_to_singbox(cfg)
                if conv:
                    outbounds.append(conv)
                    valid_tags.append(conv['tag'])

            if not outbounds:
                print("هیچ کانفیگ معتبری پیدا نشد!")
                return

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

            print(f"موفقیت‌آمیز {len(outbounds)} پروکسی به sing-box تبدیل و ذخیره شد!")
            print(f"فایل: {self.output_file}")

        except FileNotFoundError:
            print("فایل configs/proxy_configs.txt پیدا نشد!")
        except Exception as e:
            print(f"خطا: {e}")


if __name__ == '__main__':
    ConfigToSingbox().process_configs()
