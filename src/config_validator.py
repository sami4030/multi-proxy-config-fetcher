import re
import base64
import json
from typing import Optional, Tuple, List
from urllib.parse import unquote, urlparse

class ConfigValidator:
    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            s = s.rstrip('=')
            return bool(re.match(r'^[A-Za-z0-9+/\-_]*$', s))
        except:
            return False

    @staticmethod
    def decode_base64_url(s: str) -> Optional[bytes]:
        try:
            s = s.replace('-', '+').replace('_', '/')
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += '=' * padding
            return base64.b64decode(s)
        except:
            return None

    @staticmethod
    def decode_base64_text(text: str) -> Optional[str]:
        try:
            if ConfigValidator.is_base64(text):
                decoded = ConfigValidator.decode_base64_url(text)
                if decoded:
                    return decoded.decode('utf-8')
            return None
        except:
            return None
            
    @staticmethod
    def get_config_fingerprint(config: str) -> str:
        """
        برگرداندن یک شناسه منحصر به فرد برای هر کانفیگ بر اساس کلید اتصال
        مثال خروجی: "hysteria2:91.99.225.11:443:EXFdk0goSh"
                      "vless:1.1.1.1:8443:abcd1234-..."
                      "vmess:8.8.8.8:443:uuid1234"
        """
        try:
            config = config.strip()
            lower = config.lower()

            if lower.startswith(('hysteria2://', 'hy2://')):
                # hysteria2://pass@ip:port یا hysteria2://obfs-pass@ip:port?obfs-password=xxx
                parsed = urlparse(config.replace('hy2://', 'hysteria2://'))
                server = parsed.hostname or ''
                port = str(parsed.port or 443)
                # پسورد اصلی از username یا obfs-password
                password = parsed.username or ''
                if not password and 'obfs-password' in config:
                    import re
                    m = re.search(r'obfs-password=([^&\'"\s>]+)', config)
                    if m:
                        password = m.group(1)
                return f"hysteria2:{server}:{port}:{password}".lower()

            elif lower.startswith('vless://'):
                import uuid as uuid_lib
                parsed = urlparse(config)
                uuid_match = parsed.username or re.search(r'vless://([a-f0-9-]{36})', config)
                if uuid_match:
                    uuid_val = uuid_match.group(1) if hasattr(uuid_match, 'group') else uuid_match
                    server = parsed.hostname or ''
                    port = str(parsed.port or 443)
                    return f"vless:{server}:{port}:{uuid_val}".lower()

            elif lower.startswith('vmess://'):
                import json, base64
                try:
                    data = json.loads(base64.b64decode(config[8:] + '==='))
                    return f"vmess:{data.get('add','')}:{data.get('port',443)}:{data.get('id','')}".lower()
                except:
                    return config.lower()  # fallback

            elif lower.startswith('trojan://'):
                parsed = urlparse(config)
                password = parsed.username or ''
                server = parsed.hostname or ''
                port = str(parsed.port or 443)
                return f"trojan:{server}:{port}:{port}:{password}".lower()

            elif lower.startswith('ss://'):
                # ss://method:pass@server:port یا جدیدتر
                if '@' in config[5:]:
                    part = config.split('@', 1)[1].split('#')[0].split('?')[0]
                    server_port = part.split('/')[0]
                    if ':' in server_port:
                        server, port = server_port.rsplit(':', 1)
                        method_pass = config[5:].split('@')[0]
                        if ':' in method_pass:
                            method, password = method_pass.split(':', 1)
                            return f"ss:{server}:{port}:{method}:{password}".lower()
                return config.lower()

            return config.lower()  # fallback
        except:
            return config.lower()

    @staticmethod
    def clean_vmess_config(config: str) -> str:
        if "vmess://" in config:
            base64_part = config[8:]
            base64_clean = re.split(r'[^A-Za-z0-9+/=_-]', base64_part)[0]
            return f"vmess://{base64_clean}"
        return config

    @staticmethod
    def normalize_hysteria2_protocol(config: str) -> str:
        if config.startswith('hy2://'):
            return config.replace('hy2://', 'hysteria2://', 1)
        return config

    @staticmethod
    def is_vmess_config(config: str) -> bool:
        try:
            if not config.startswith('vmess://'):
                return False
            base64_part = config[8:]
            decoded = ConfigValidator.decode_base64_url(base64_part)
            if decoded:
                json.loads(decoded)
                return True
            return False
        except:
            return False

    @staticmethod
    def is_tuic_config(config: str) -> bool:
        try:
            if config.startswith('tuic://'):
                parsed = urlparse(config)
                return bool(parsed.netloc and ':' in parsed.netloc)
            return False
        except:
            return False

    @staticmethod
    def convert_ssconf_to_https(url: str) -> str:
        if url.startswith('ssconf://'):
            return url.replace('ssconf://', 'https://', 1)
        return url

    @staticmethod
    def is_base64_config(config: str) -> Tuple[bool, str]:
        protocols = ['vmess://', 'vless://', 'ss://', 'tuic://']
        for protocol in protocols:
            if config.startswith(protocol):
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if (ConfigValidator.is_base64(decoded_url) or 
                    ConfigValidator.is_base64(base64_part)):
                    return True, protocol[:-3]
        return False, ''

    @staticmethod
    def check_base64_content(text: str) -> Optional[str]:
        try:
            decoded_text = ConfigValidator.decode_base64_text(text)
            if decoded_text:
                protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 'wireguard://', 'tuic://', 'ssconf://']
                for protocol in protocols:
                    if protocol in decoded_text:
                        return decoded_text
            return None
        except:
            return None

    @staticmethod
    def split_configs(text: str) -> List[str]:
        configs = []
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if ConfigValidator.is_base64(line):
                decoded_content = ConfigValidator.check_base64_content(line)
                if decoded_content:
                    text = decoded_content
                    
            protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 'wireguard://', 'tuic://', 'ssconf://']
            current_pos = 0
            text_length = len(text)
            
            while current_pos < text_length:
                next_config_start = text_length
                matching_protocol = None
                
                for protocol in protocols:
                    protocol_pos = text.find(protocol, current_pos)
                    if protocol_pos != -1 and protocol_pos < next_config_start:
                        next_config_start = protocol_pos
                        matching_protocol = protocol
                
                if matching_protocol:
                    if current_pos < next_config_start and configs:
                        current_config = text[current_pos:next_config_start].strip()
                        if ConfigValidator.is_valid_config(current_config):
                            configs.append(current_config)
                    
                    current_pos = next_config_start
                    next_protocol_pos = text_length
                    
                    for protocol in protocols:
                        pos = text.find(protocol, next_config_start + len(matching_protocol))
                        if pos != -1 and pos < next_protocol_pos:
                            next_protocol_pos = pos
                    
                    current_config = text[next_config_start:next_protocol_pos].strip()
                    if matching_protocol == "vmess://":
                        current_config = ConfigValidator.clean_vmess_config(current_config)
                    elif matching_protocol == "hy2://":
                        current_config = ConfigValidator.normalize_hysteria2_protocol(current_config)
                    if ConfigValidator.is_valid_config(current_config):
                        configs.append(current_config)
                    
                    current_pos = next_protocol_pos
                else:
                    break
                    
        return configs

    @staticmethod
    def clean_config(config: str) -> str:
        config = re.sub(r'[\U0001F300-\U0001F9FF]', '', config)
        config = re.sub(r'[\x00-\x08\x0B-\x1F\x7F-\x9F]', '', config)
        config = re.sub(r'[^\S\r\n]+', ' ', config)
        config = config.strip()
        return config

    @staticmethod
    def is_valid_config(config: str) -> bool:
        if not config:
            return False
            
        protocols = ['vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria2://', 'hy2://', 'wireguard://', 'tuic://', 'ssconf://']
        return any(config.startswith(p) for p in protocols)

    @classmethod
    def validate_protocol_config(cls, config: str, protocol: str) -> bool:
        try:
            if protocol in ['vmess://', 'vless://', 'ss://', 'tuic://']:
                if protocol == 'vmess://':
                    return cls.is_vmess_config(config)
                if protocol == 'tuic://':
                    return cls.is_tuic_config(config)
                base64_part = config[len(protocol):]
                decoded_url = unquote(base64_part)
                if cls.is_base64(decoded_url) or cls.is_base64(base64_part):
                    return True
                if cls.decode_base64_url(base64_part) or cls.decode_base64_url(decoded_url):
                    return True
            elif protocol in ['trojan://', 'hysteria2://', 'hy2://', 'wireguard://']:
                parsed = urlparse(config)
                return bool(parsed.netloc and '@' in parsed.netloc)
            elif protocol == 'ssconf://':
                return True
            return False
        except:
            return False
