import socket
from _socket import gaierror
from asyncio import gather
from typing import Dict, List, Optional

import dns.exception
from asyncstdlib.functools import lru_cache

from .core import cl, logger


socket.setdefaulttimeout(3)


@lru_cache(maxsize=1024)
async def resolve_host(host: str) -> str:
    if dns.inet.is_address(host):
        return host
    addrinfo = socket.getaddrinfo(host, 80)
    answer = addrinfo[0][-1][0]
    logger.info(f"{cl.RED}{host}{cl.RESET} {cl.YELLOW}resolved to {cl.BLUE}{answer}{cl.RESET}")
    return answer


async def safe_resolve_host(host: str) -> Optional[str]:
    try:
        resolved = await resolve_host(host)
        if resolved in ["127.0.0.1", "0.0.0.0"]:
            raise dns.exception.DNSException('resolved to localhost')
        return resolved
    except (dns.exception.DNSException, gaierror):
        logger.warning(
            f"{cl.YELLOW}Ціль {cl.BLUE}{host}{cl.YELLOW} не доступна "
            f"і {cl.RED}не буде атакована{cl.RESET}"
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
