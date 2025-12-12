# fetch_configs.py - نسخه یکپارچه با فیلتر پیشرفته
import re
import os
import time
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
from collections import OrderedDict
import requests
from bs4 import BeautifulSoup
from config import ProxyConfig, ChannelConfig
from config_validator import ConfigValidator

# Import فیلتر (اگه فایل وجود داشته باشه)
try:
    from config_filter import ConfigFilter
    import user_settings
    FILTERING_AVAILABLE = True
except ImportError:
    FILTERING_AVAILABLE = False
    print("⚠️  config_filter.py not found. Advanced filtering disabled.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        
        # 🔥 دیکشنری برای نگه‌داشتن آخرین نسخه هر کانفیگ
        # Key = fingerprint, Value = (config_string, timestamp, channel_priority)
        self.unique_configs: OrderedDict[str, tuple] = OrderedDict()
        
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {}
        self.session = requests.Session()
        self.session.headers.update(config.HEADERS)
        
        # سیستم فیلترینگ پیشرفته
        if FILTERING_AVAILABLE:
            self.filter_system = ConfigFilter(user_settings)
            logger.info("✅ Advanced filtering system enabled")
        else:
            self.filter_system = None
            logger.warning("⚠️  Advanced filtering system disabled")

    def extract_config(self, text: str, start_index: int, protocol: str) -> Optional[str]:
        """استخراج یک کانفیگ از متن"""
        try:
            remaining_text = text[start_index:]
            configs = self.validator.split_configs(remaining_text)
            
            for config in configs:
                if config.startswith(protocol):
                    clean_config = self.validator.clean_config(config)
                    if self.validator.validate_protocol_config(clean_config, protocol):
                        return clean_config
            return None
        except Exception as e:
            logger.error(f"Error in extract_config: {str(e)}")
            return None

    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        """دریافت URL با retry"""
        backoff = 1
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logger.error(f"Failed to fetch {url} after {self.config.MAX_RETRIES} attempts: {str(e)}")
                    return None
                wait_time = min(self.config.RETRY_DELAY * backoff, 60)
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
                backoff *= 2
        return None

    def fetch_ssconf_configs(self, url: str) -> List[str]:
        """دریافت کانفیگ‌های ssconf"""
        https_url = self.validator.convert_ssconf_to_https(url)
        configs = []
        
        response = self.fetch_with_retry(https_url)
        if response and response.text.strip():
            text = response.text.strip()
            if self.validator.is_base64(text):
                decoded = self.validator.decode_base64_text(text)
                if decoded:
                    text = decoded
            
            if text.startswith('ss://'):
                configs.append(text)
            else:
                configs.extend(self.validator.split_configs(text))
            
        return configs

    def check_and_decode_base64(self, text: str) -> str:
        """چک و دیکد base64"""
        if self.validator.is_base64(text):
            decoded = self.validator.decode_base64_text(text)
            if decoded:
                return decoded
        return text

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        """
        دریافت کانفیگ‌ها از یک منبع
        با اعمال فیلتر پیشرفته و حذف تکراری
        """
        raw_configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}

        start_time = time.time()

        # دریافت ssconf
        if channel.url.startswith('ssconf://'):
            raw_configs.extend(self.fetch_ssconf_configs(channel.url))

        # دریافت از تلگرام
        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return []

        response_time = time.time() - start_time
        soup = BeautifulSoup(response.text, 'html.parser')

        # استخراج همه پیام‌ها
        messages = soup.find_all('div', class_='tgme_widget_message')

        for message in messages:
            text = message.get_text(separator='\n')

            # چک تاریخ
            message_date = self.extract_date_from_message(message)
            if not self.is_config_valid(text, message_date):
                continue

            # استخراج لینک‌ها
            potential_links = re.findall(r'[a-zA-Z0-9+/_-]+://[^\s<>"\']+', text)
            for link in potential_links:
                link = link.strip()
                if any(link.startswith(proto) for proto in self.config.SUPPORTED_PROTOCOLS):
                    raw_configs.append(link)
                elif link.startswith('ssconf://'):
                    raw_configs.extend(self.fetch_ssconf_configs(link))

            # دیکد base64
            if self.validator.is_base64(text.strip()):
                decoded = self.validator.decode_base64_text(text.strip())
                if decoded:
                    raw_configs.extend(self.validator.split_configs(decoded))

            # استخراج مستقیم
            raw_configs.extend(self.validator.split_configs(text))

        channel.metrics.total_configs = len(raw_configs)
        logger.info(f"📥 Extracted {len(raw_configs)} raw configs from {channel.url}")

        # ====================================================================
        # 🔥 مرحله 1: اعمال فیلتر پیشرفته (country, protocol, port, server)
        # ====================================================================
        if self.filter_system and FILTERING_AVAILABLE:
            channel_filters = getattr(channel, 'filters', {
                'servers': ['*'],
                'countries': ['*'],
                'protocols': ['*'],
                'ports': ['*']
            })
            
            logger.info(f"🔍 Applying advanced filters...")
            filtered_configs = self.filter_system.filter_configs(raw_configs, channel_filters)
            logger.info(f"✅ After advanced filtering: {len(filtered_configs)}/{len(raw_configs)} configs")
        else:
            filtered_configs = raw_configs
            logger.info(f"⚠️  Advanced filtering skipped (not available)")

        # ====================================================================
        # 🔥 مرحله 2: حذف تکراری + نگه‌داشتن آخرین نسخه
        # ====================================================================
        current_time = time.time()
        channel_priority = getattr(channel, 'priority', 5)
        
        for cfg in filtered_configs:
            fingerprint = ConfigValidator.get_config_fingerprint(cfg)
            
            if fingerprint and fingerprint != cfg.lower():
                # اگه این fingerprint قبلاً دیده شده
                if fingerprint in self.unique_configs:
                    old_config, old_time, old_priority = self.unique_configs[fingerprint]
                    
                    # 🔥 استراتژی: آخرین نسخه با اولویت بالاتر
                    # اگه کانال جدید اولویت بالاتر داره، یا زمان جدیدتره → جایگزین
                    if channel_priority >= old_priority:
                        self.unique_configs[fingerprint] = (cfg, current_time, channel_priority)
                        logger.debug(f"🔄 Updated duplicate: {fingerprint[:20]}... (priority: {channel_priority})")
                    else:
                        logger.debug(f"⏭️  Skipped older duplicate: {fingerprint[:20]}...")
                else:
                    # اولین بار دیده شده
                    self.unique_configs[fingerprint] = (cfg, current_time, channel_priority)

        # ====================================================================
        # 🔥 مرحله 3: پردازش کانفیگ‌های منحصر به فرد
        # ====================================================================
        final_configs = []
        for fingerprint, (cfg, timestamp, priority) in self.unique_configs.items():
            processed = self.process_config(cfg, channel)
            if processed:
                final_configs.extend(processed)
                channel.metrics.valid_configs += len(processed)
                channel.metrics.unique_configs += 1

        logger.info(f"📊 Channel stats: {channel.metrics.valid_configs} valid, {channel.metrics.unique_configs} unique")

        # آپدیت آمار کانال
        if final_configs:
            self.config.update_channel_stats(channel, True, response_time)
        else:
            self.config.update_channel_stats(channel, False)

        return final_configs

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        """
        پردازش و اعتبارسنجی یک کانفیگ
        """
        processed_configs = []

        # نرمال‌سازی
        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)

        for protocol in self.config.SUPPORTED_PROTOCOLS:
            aliases = self.config.SUPPORTED_PROTOCOLS[protocol].get('aliases', [])
            protocol_match = False

            if config.startswith(protocol):
                protocol_match = True
            else:
                for alias in aliases:
                    if config.startswith(alias):
                        config = config.replace(alias, protocol, 1)
                        protocol_match = True
                        break

            if not protocol_match:
                continue

            if not self.config.is_protocol_enabled(protocol):
                continue

            if protocol == "vmess://":
                config = self.validator.clean_vmess_config(config)

            clean_config = self.validator.clean_config(config)

            if not self.validator.validate_protocol_config(clean_config, protocol):
                continue

            # اضافه به نتیجه
            channel.metrics.protocol_counts[protocol] = channel.metrics.protocol_counts.get(protocol, 0) + 1
            processed_configs.append(clean_config)
            self.protocol_counts[protocol] += 1

            break  # فقط یک پروتکل

        return processed_configs

    def extract_date_from_message(self, message) -> Optional[datetime]:
        """استخراج تاریخ از پیام"""
        try:
            time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
            if time_element and 'datetime' in time_element.attrs:
                return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
        except Exception:
            pass
        return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        """چک اعتبار بر اساس تاریخ"""
        if not date:
            return True
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff_date

    def balance_protocols(self, configs: List[str]) -> List[str]:
        """تعادل پروتکل‌ها"""
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        
        for config in configs:
            if config.startswith('hy2://'):
                config = self.validator.normalize_hysteria2_protocol(config)
                
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if config.startswith(protocol):
                    protocol_configs[protocol].append(config)
                    break
        
        total_configs = sum(len(configs) for configs in protocol_configs.values())
        if total_configs == 0:
            return []
            
        balanced_configs: List[str] = []
        sorted_protocols = sorted(
            protocol_configs.items(),
            key=lambda x: (
                self.config.SUPPORTED_PROTOCOLS[x[0]]["priority"],
                len(x[1])
            ),
            reverse=True
        )
        
        for protocol, protocol_config_list in sorted_protocols:
            protocol_info = self.config.SUPPORTED_PROTOCOLS[protocol]
            if len(protocol_config_list) >= protocol_info["min_configs"]:
                max_configs = min(
                    protocol_info["max_configs"],
                    len(protocol_config_list)
                )
                balanced_configs.extend(protocol_config_list[:max_configs])
            elif protocol_info["flexible_max"] and len(protocol_config_list) > 0:
                balanced_configs.extend(protocol_config_list)
        
        return balanced_configs

    def fetch_all_configs(self) -> List[str]:
        """
        دریافت از همه کانال‌ها
        با حفظ فقط آخرین نسخه از هر کانفیگ تکراری
        """
        # پاک کردن دیکشنری کانفیگ‌ها
        self.unique_configs.clear()
        
        enabled_channels = self.config.get_enabled_channels()
        total_channels = len(enabled_channels)
        
        # مرتب‌سازی بر اساس priority (اگه فعال باشه)
        if FILTERING_AVAILABLE and hasattr(user_settings, 'SORT_BY_PRIORITY') and user_settings.SORT_BY_PRIORITY:
            enabled_channels.sort(key=lambda x: getattr(x, 'priority', 5), reverse=True)
            logger.info("📊 Channels sorted by priority")
        
        logger.info(f"🚀 Starting fetch from {total_channels} channels...")
        
        for idx, channel in enumerate(enabled_channels, 1):
            logger.info(f"\n{'='*70}")
            logger.info(f"📡 Processing channel {idx}/{total_channels}")
            logger.info(f"🔗 URL: {channel.url}")
            logger.info(f"⭐ Priority: {getattr(channel, 'priority', 5)}")
            logger.info(f"{'='*70}")
            
            channel_configs = self.fetch_configs_from_source(channel)
            
            if idx < total_channels:
                time.sleep(2)
        
        # تبدیل دیکشنری به لیست (فقط آخرین نسخه‌ها)
        final_configs = [cfg for cfg, _, _ in self.unique_configs.values()]
        
        logger.info(f"\n{'='*70}")
        logger.info(f"📊 Final Statistics")
        logger.info(f"{'='*70}")
        logger.info(f"Total unique configs: {len(final_configs)}")
        logger.info(f"Protocol breakdown:")
        for protocol, count in sorted(self.protocol_counts.items()):
            if count > 0:
                logger.info(f"  {protocol}: {count}")
        logger.info(f"{'='*70}\n")
        
        if final_configs:
            final_configs = self.balance_protocols(final_configs)
            return final_configs
        
        return []


def save_configs(configs: List[str], config: ProxyConfig):
    """ذخیره کانفیگ‌ها"""
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            header = """//profile-title: base64:8J+RvUFub255bW91cy3wnZWP
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/BXAMbot
//profile-web-page-url: https://github.com/4n0nymou3

"""
            f.write(header)
            for config_line in configs:
                f.write(config_line + '\n\n')
        logger.info(f"✅ Successfully saved {len(configs)} configs to {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"❌ Error saving configs: {str(e)}")


def save_channel_stats(config: ProxyConfig):
    """ذخیره آمار کانال‌ها"""
    try:
        stats = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channels': []
        }
        
        for channel in config.SOURCE_URLS:
            channel_stats = {
                'url': channel.url,
                'enabled': channel.enabled,
                'priority': getattr(channel, 'priority', 5),
                'filters': getattr(channel, 'filters', {}),
                'metrics': {
                    'total_configs': channel.metrics.total_configs,
                    'valid_configs': channel.metrics.valid_configs,
                    'unique_configs': channel.metrics.unique_configs,
                    'avg_response_time': round(channel.metrics.avg_response_time, 2),
                    'success_count': channel.metrics.success_count,
                    'fail_count': channel.metrics.fail_count,
                    'overall_score': round(channel.metrics.overall_score, 2),
                    'last_success': channel.metrics.last_success_time.replace(tzinfo=timezone.utc).isoformat() if channel.metrics.last_success_time else None,
                    'protocol_counts': channel.metrics.protocol_counts
                }
            }
            stats['channels'].append(channel_stats)
            
        os.makedirs(os.path.dirname(config.STATS_FILE), exist_ok=True)
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
            
        logger.info(f"✅ Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"❌ Error saving channel statistics: {str(e)}")


def main():
    """تابع اصلی"""
    try:
        logger.info("="*70)
        logger.info("🚀 Starting Proxy Config Fetcher")
        logger.info("="*70)
        
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        
        # نمایش تنظیمات
        if FILTERING_AVAILABLE:
            logger.info("✅ Advanced filtering: ENABLED")
            if hasattr(user_settings, 'ENABLE_FILTERING'):
                logger.info(f"   Filter mode: {getattr(user_settings, 'FILTER_MODE', 'AND')}")
                logger.info(f"   Wildcard: {getattr(user_settings, 'ENABLE_WILDCARD', True)}")
        else:
            logger.info("⚠️  Advanced filtering: DISABLED")
        
        logger.info(f"📝 Maximum power: {config.use_maximum_power}")
        logger.info(f"🎯 Target configs: {config.specific_config_count if not config.use_maximum_power else 'unlimited'}")
        logger.info(f"📅 Max age: {config.MAX_CONFIG_AGE_DAYS} days")
        logger.info(f"🔗 Active channels: {len(config.get_enabled_channels())}")
        logger.info("")
        
        # دریافت کانفیگ‌ها
        configs = fetcher.fetch_all_configs()
        
        if configs:
            save_configs(configs, config)
            logger.info(f"\n✅ Successfully processed {len(configs)} unique configs")
            logger.info(f"📊 Protocol breakdown:")
            for protocol, count in fetcher.protocol_counts.items():
                if count > 0:
                    logger.info(f"   {protocol}: {count} configs")
        else:
            logger.error("❌ No valid configs found!")
            
        save_channel_stats(config)
        
        logger.info("\n" + "="*70)
        logger.info("✅ Fetch completed successfully!")
        logger.info("="*70)
            
    except Exception as e:
        logger.error(f"❌ Error in main execution: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
