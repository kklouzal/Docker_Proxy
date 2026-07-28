from __future__ import annotations

from dataclasses import dataclass

LOCAL_DOMAIN_SUFFIXES = (".local", ".localdomain", ".home.arpa", ".localhost")
PAC_IPV4_LOOPBACK_CIDR = "127.0.0.0/8"
PAC_PRIVATE_LOCAL_IPV4_NETS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)
PAC_PRIVATE_LOCAL_IPV6_HEXTET_RANGES = (
    ("fc00::/7", 0xFC00, 0xFDFF),
    ("fe80::/10", 0xFE80, 0xFEBF),
)
PAC_PRIVATE_LOCAL_IPV6_NETS = tuple(
    cidr for cidr, _first, _last in PAC_PRIVATE_LOCAL_IPV6_HEXTET_RANGES
)


@dataclass(frozen=True)
class PacDirectDestinationClass:
    label: str
    values: tuple[str, ...]
    sample_hosts: tuple[str, ...]
    requires_private_toggle: bool


PAC_ALWAYS_DIRECT_DESTINATION_CLASSES = (
    PacDirectDestinationClass(
        label="Always DIRECT local hostnames and loopback",
        values=("localhost", "plain hostnames", PAC_IPV4_LOOPBACK_CIDR, "::1/128"),
        sample_hosts=("localhost", "printer", "127.5.6.7", "::1"),
        requires_private_toggle=False,
    ),
    PacDirectDestinationClass(
        label="Always DIRECT local DNS suffixes",
        values=LOCAL_DOMAIN_SUFFIXES,
        sample_hosts=("printer.local", "gateway.home.arpa"),
        requires_private_toggle=False,
    ),
)

PAC_PRIVATE_TOGGLE_DESTINATION_CLASSES = (
    PacDirectDestinationClass(
        label="Private PAC IPv4 private ranges",
        values=PAC_PRIVATE_LOCAL_IPV4_NETS[:3],
        sample_hosts=("10.1.2.3", "172.16.5.10", "192.168.10.20"),
        requires_private_toggle=True,
    ),
    PacDirectDestinationClass(
        label="Private PAC IPv4 link-local range",
        values=(PAC_PRIVATE_LOCAL_IPV4_NETS[3],),
        sample_hosts=("169.254.1.5",),
        requires_private_toggle=True,
    ),
    PacDirectDestinationClass(
        label="Private PAC IPv6 unique-local range",
        values=(PAC_PRIVATE_LOCAL_IPV6_NETS[0],),
        sample_hosts=("fc00::1", "fd12:3456::1"),
        requires_private_toggle=True,
    ),
    PacDirectDestinationClass(
        label="Private PAC IPv6 link-local range",
        values=(PAC_PRIVATE_LOCAL_IPV6_NETS[1],),
        sample_hosts=("fe80::1", "febf::1"),
        requires_private_toggle=True,
    ),
)

PAC_PRIVATE_LOCAL_DESTINATION_CLASSES = (
    *PAC_ALWAYS_DIRECT_DESTINATION_CLASSES,
    *PAC_PRIVATE_TOGGLE_DESTINATION_CLASSES,
)


def pac_private_local_destination_metadata() -> list[PacDirectDestinationClass]:
    return list(PAC_PRIVATE_LOCAL_DESTINATION_CLASSES)


def pac_private_local_destination_values() -> list[str]:
    values: list[str] = []
    for group in PAC_PRIVATE_LOCAL_DESTINATION_CLASSES:
        values.extend(group.values)
    return values
