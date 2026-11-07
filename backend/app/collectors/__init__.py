from .base import Result
from .network import ping, tcp, http, internet
from .snmp import snmp
from .ssh import ssh
from .esxi import esxi
from .pfsense import pfsense
from .proxmox import proxmox

COLLECTORS = {
    "ping": ping,
    "tcp": tcp,
    "http": http,
    "internet": internet,
    "snmp": snmp,
    "ssh": ssh,
    "esxi": esxi,
    "pfsense": pfsense,
    "proxmox": proxmox,
}

__all__ = ["COLLECTORS", "Result"]
