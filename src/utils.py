import math
import random
import struct
import time
from _md5 import md5
from collections import defaultdict
from socket import inet_ntoa
from string import ascii_letters, digits
from typing import Dict, Optional, Tuple
from zlib import crc32

from jinja2 import Environment

from src.proxies import NoProxySet
from src.targets import Target
from .vendor.rotate import params as rotate_params, suffix as rotate_suffix


cyryllic_letters = "АаБбВвГгДдЕеЁёЖжЗзИиЙйКкЛлМмНнОоПпРрСсТтУуФфХхЦцЧчШшЩщЪъЫыЬьЭэЮюЯя"


JINJA = Environment()


class Tools:
    @staticmethod
    def humanbits(i: float) -> str:
        MULTIPLES = ["Bit", "kBit", "MBit", "GBit"]
        if i > 0:
            base = 1024
            multiple = math.trunc(math.log2(i) / math.log2(base))
            value = i / pow(base, multiple)
            return f'{value:.2f} {MULTIPLES[multiple]}'
        else:
            return '0 Bit'

    @staticmethod
    def humanformat(i: float) -> str:
        MULTIPLES = ['', 'k', 'M', 'G']
        if i > 0:
            base = 1000
            multiple = math.trunc(math.log2(i) / math.log2(base))
            value = i / pow(base, multiple)
            return f'{value:.2f}{MULTIPLES[multiple]}'
        else:
            return '0'

    @staticmethod
    def parse_params(target: Target, proxies):
        url, ip = target.url, target.addr
        result = url.host.lower().endswith(rotate_suffix)
        if result:
            return random.choice(rotate_params), NoProxySet
        return (url, ip), proxies

    @staticmethod
    def rand_str(length=16, alphabet=ascii_letters + digits + cyryllic_letters):
        return ''.join(random.choices(alphabet, k=length))

    @staticmethod
    def rand_ipv4():
        return inet_ntoa(
            struct.pack('>I', random.randint(1, 0xffffffff))
        )


class Templater:
    _render_max_mem = 65536  # 64 kb
    _context = {
        "int": random.randint,
        "str": Tools.rand_str,
        "digits": digits,
        "letters": ascii_letters,
    }

    @classmethod
    def render(cls, raw: str, cache: dict):
        if '{{' not in raw:
            return raw

        render_cache = cache.setdefault('rendered', defaultdict(list))
        render_max_threshold = cls._render_max_mem // len(raw)
        already_rendered = render_cache[raw]
        if len(already_rendered) >= render_max_threshold:
            return random.choice(already_rendered)

        template_cache = cache.setdefault('template', {})
        template = template_cache.get(raw)
        if template is None:
            template = JINJA.from_string(raw)
            template_cache[raw] = template

        rendered = template.render(cls._context)
        already_rendered.append(rendered)
        return rendered


class GOSSolver:
    DEFAULT_A = 1800
    MAX_RPC = 100
    OWN_IP_KEY = "__OWN__"

    _path = bytes.fromhex(
        "68747470733a2f2f7777772e676f7375736c7567692e72752f5f5f6a7363682f736368656d612e6a736f6e").decode()
    _verifier = bytes.fromhex("5f5f6a7363682f7374617469632f7363726970742e6a73")

    # this is going to be shared between all tasks
    # but only within a single process. we rely on
    # async execution being done on the same thread
    # to avoid necessity to keep locks around
    _cache = {}

    @property
    def path(self) -> str:
        return self._path

    def bypass(self, resp: bytes) -> bool:
        return self._verifier not in resp

    def time_bucket(self, a):
        ts = int(time.time())
        return ts - ts % a

    def lookup(self, a, ip) -> Optional[Tuple[int, str, Dict[str, str]]]:
        current = self._cache.get(ip)
        if current is None:
            return None
        next_bucket, _, _ = current
        now_bucket = self.time_bucket(a)
        if next_bucket > now_bucket:
            return current
        # evict from the cache
        del self._cache[ip]
        return None

    def solve(self, ua, resp, *, cache_key: str) -> Tuple[int, Dict[str, str]]:
        a, ip, cn = resp["a"], resp["ip"], resp["cn"]
        bucket = self.time_bucket(a)
        value = f"{ua}:{ip}:{bucket}"

        hasher = md5
        for pos in range(10_000_000):
            response = hasher(f'{value}{pos}'.encode()).hexdigest()
            if response[6:10] == '3fe3':
                cookies = {
                    cn: response.upper(),
                    f"{cn}_2": pos,
                    f"{cn}_3": crc32(value.encode())
                }
                self._cache[cache_key] = (bucket + a, ua, cookies)
                return bucket + a, cookies
        raise ValueError("invalid input")
