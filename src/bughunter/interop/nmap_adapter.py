from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NmapHost:
    ip: str
    hostname: str = ""
    state: str = "up"
    ports: list[dict[str, Any]] = field(default_factory=list)
    os_guess: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


def parse_nmap_xml(xml_path: str | Path) -> list[NmapHost]:
    hosts: list[NmapHost] = []
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    for host_el in root.findall(".//host"):
        try:
            state_el = host_el.find("status")
            state = state_el.get("state", "up") if state_el is not None else "up"

            ip = ""
            hostname = ""
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ip = addr_el.get("addr", "")
                elif addr_el.get("addrtype") == "ipv6":
                    if not ip:
                        ip = addr_el.get("addr", "")

            for hostname_el in host_el.findall(".//hostname"):
                name = hostname_el.get("name", "")
                if name:
                    hostname = name

            ports = []
            for port_el in host_el.findall(".//port"):
                port_id = port_el.get("portid", "")
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                service_name = ""
                service_product = ""
                service_version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    service_product = service_el.get("product", "")
                    service_version = service_el.get("version", "")

                ports.append({
                    "port": int(port_id) if port_id.isdigit() else 0,
                    "protocol": protocol,
                    "state": port_state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                })

            scripts = {}
            for script_el in host_el.findall(".//script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")
                if script_id:
                    scripts[script_id] = script_output

            os_guess = ""
            for osmatch_el in host_el.findall(".//osmatch"):
                os_guess = osmatch_el.get("name", "")
                break

            hosts.append(NmapHost(
                ip=ip,
                hostname=hostname,
                state=state,
                ports=ports,
                os_guess=os_guess,
                scripts=scripts,
            ))
        except Exception:
            continue

    return hosts


def nmap_to_scan_targets(hosts: list[NmapHost]) -> list[dict[str, Any]]:
    targets = []
    for host in hosts:
        if host.state != "up":
            continue
        target = {
            "ip": host.ip,
            "hostname": host.hostname,
            "ports": [p["port"] for p in host.ports if p["state"] == "open"],
            "services": [f"{p['service']}:{p['port']}" for p in host.ports if p["state"] == "open"],
        }
        targets.append(target)
    return targets
