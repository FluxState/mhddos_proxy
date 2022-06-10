import time
import socket
from _socket import gaierror
from asyncio import gather
from typing import Dict, List, Optional

import dns.exception
from asyncstdlib.functools import lru_cache

from .core import cl, logger
from .i18n import translate as t


socket.setdefaulttimeout(3)

CACHE_FOR = 30 * 60


@lru_cache(maxsize=1024)
async def _resolve_host(host: str, ttl_hash=None) -> str:
    if dns.inet.is_address(host):
        return host
    addrinfo = socket.getaddrinfo(host, 80)
    answer = addrinfo[0][-1][0]
    logger.info(f"{cl.RED}{host}{cl.RESET} {cl.YELLOW}resolved to {cl.BLUE}{answer}{cl.RESET}")
    return answer


async def safe_resolve_host(host: str) -> Optional[str]:
    try:
        resolved = await _resolve_host(host, int(time.time() / CACHE_FOR))
        if resolved ["127.0.0.1", "0.0.0.0"]:
            raise dns.exception.DNSException('resolved to localhost')
        return resolved
    except (dns.exception.DNSException, gaierror):
        logger.warning(
            f"{cl.MAGENTA}{t('Target')} {cl.BLUE}{host}{cl.MAGENTA}"
            f""" {t("is not available and won't be attacked")}{cl.RESET}"""
        )


async def resolve_all(hosts: List[str]) -> Dict[str, str]:
    unresolved_hosts = list(set(
        host
        for host in hosts
        if not dns.inet.is_address(host)
    ))
    answers = await gather(*[
        safe_resolve_host(h)
        for h in unresolved_hosts
    ])
    ips = dict(zip(unresolved_hosts, answers))
    return {
        host: ips.get(host, host)
        for host in hosts
    }


async def resolve_all_targets(targets: List["Target"]) -> List["Target"]:
    unresolved_hosts = list(set(
        target.url.host
        for target in targets
        if not target.is_resolved
    ))
    ips = await resolve_all(unresolved_hosts)
    for target in targets:
        if not target.is_resolved:
            target.addr = ips.get(target.url.host)
    return targets
