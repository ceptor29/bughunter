from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

import json


@dataclass
class BurpRequest:
    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    host: str = ""
    port: int = 0
    protocol: str = ""
    path: str = ""
    status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    timestamp: str = ""
    comments: str = ""
    tags: list[str] = field(default_factory=list)


def parse_burp_xml(xml_path: str | Path) -> list[BurpRequest]:
    requests: list[BurpRequest] = []
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    for item in root.findall(".//item"):
        try:
            url_el = item.find("url")
            url = url_el.text if url_el is not None and url_el.text else ""

            method_el = item.find("method")
            method = method_el.text if method_el is not None and method_el.text else "GET"

            host_el = item.find("host")
            host = host_el.text if host_el is not None and host_el.text else ""

            port_el = item.find("port")
            port = int(port_el.text) if port_el is not None and port_el.text else 0

            protocol_el = item.find("protocol")
            protocol = protocol_el.text if protocol_el is not None and protocol_el.text else "http"

            path_el = item.find("path")
            path = path_el.text if path_el is not None and path_el.text else ""

            request_el = item.find("request")
            request_headers: dict[str, str] = {}
            request_body = ""
            if request_el is not None:
                req_base64 = request_el.get("base64", "false") == "true"
                req_text = request_el.text or ""
                if req_base64:
                    import base64
                    try:
                        req_text = base64.b64decode(req_text).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                if "\r\n\r\n" in req_text:
                    header_part, _, request_body = req_text.partition("\r\n\r\n")
                else:
                    header_part = req_text
                for line in header_part.split("\r\n"):
                    if ":" in line:
                        k, _, v = line.partition(":")
                        request_headers[k.strip()] = v.strip()

            response_el = item.find("response")
            response_headers: dict[str, str] = {}
            response_body = ""
            status = 0
            if response_el is not None:
                resp_base64 = response_el.get("base64", "false") == "true"
                resp_text = response_el.text or ""
                if resp_base64:
                    import base64
                    try:
                        resp_text = base64.b64decode(resp_text).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                if "\r\n\r\n" in resp_text:
                    resp_header_part, _, response_body = resp_text.partition("\r\n\r\n")
                else:
                    resp_header_part = resp_text
                first_line = resp_header_part.split("\r\n")[0] if resp_header_part else ""
                status_match = re.search(r"(\d{3})", first_line)
                if status_match:
                    status = int(status_match.group(1))
                for line in resp_header_part.split("\r\n")[1:]:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        response_headers[k.strip()] = v.strip()

            comment_el = item.find("comment")
            comments = comment_el.text if comment_el is not None and comment_el.text else ""

            timestamp_el = item.find("time")
            timestamp = timestamp_el.text if timestamp_el is not None and timestamp_el.text else ""

            requests.append(BurpRequest(
                url=url,
                method=method.upper(),
                headers=request_headers,
                body=request_body,
                host=host,
                port=port,
                protocol=protocol,
                path=path,
                status=status,
                response_headers=response_headers,
                response_body=response_body,
                timestamp=timestamp,
                comments=comments,
            ))
        except Exception:
            continue

    return requests


def parse_burp_json(json_path: str | Path) -> list[BurpRequest]:
    requests: list[BurpRequest] = []
    with open(json_path) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("histItems", data.get("items", []))

    for item in items:
        try:
            url = item.get("url", "")
            method = item.get("method", "GET").upper()
            host = item.get("host", "")
            port = item.get("port", 0)
            protocol = item.get("protocol", "http")
            path = item.get("path", "")
            status = item.get("status", 0)

            request_headers = item.get("headers", {})
            request_body = item.get("body", "")
            if not request_body and "request" in item:
                request_body = item["request"]

            response_headers = item.get("responseHeaders", {})
            response_body = item.get("responseBody", "")
            if not response_body and "response" in item:
                response_body = item["response"]

            comments = item.get("comments", "")
            timestamp = item.get("time", "")

            requests.append(BurpRequest(
                url=url,
                method=method,
                headers=request_headers,
                body=request_body,
                host=host,
                port=port,
                protocol=protocol,
                path=path,
                status=status,
                response_headers=response_headers,
                response_body=response_body,
                timestamp=timestamp,
                comments=comments,
            ))
        except Exception:
            continue

    return requests


def load_burp_state(path: str | Path) -> list[BurpRequest]:
    p = Path(path)
    if p.suffix.lower() == ".xml":
        return parse_burp_xml(p)
    elif p.suffix.lower() == ".json":
        return parse_burp_json(p)
    else:
        try:
            return parse_burp_xml(p)
        except Exception:
            return parse_burp_json(p)


def burp_to_scan_context(requests: list[BurpRequest]) -> dict[str, Any]:
    hosts: set[str] = set()
    urls: list[str] = []
    methods: dict[str, int] = {}
    params: list[dict[str, str]] = []
    auth_headers: dict[str, str] = {}

    for req in requests:
        if req.host:
            hosts.add(req.host)
        urls.append(req.url)
        methods[req.method] = methods.get(req.method, 0) + 1

        parsed = urlparse(req.url)
        query_params = parse_qs(parsed.query)
        for k, v in query_params.items():
            params.append({"name": k, "value": v[0] if v else "", "source": "query", "url": req.url})

        if req.body:
            for pair in req.body.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    params.append({"name": k, "value": v, "source": "body", "url": req.url})

        for k, v in req.headers.items():
            if k.lower() in ("authorization", "cookie", "x-api-key", "x-csrf-token"):
                auth_headers[k] = v

    return {
        "hosts": list(hosts),
        "urls": urls,
        "methods": methods,
        "params": params,
        "auth_headers": auth_headers,
        "total_requests": len(requests),
    }


def extract_endpoints_from_burp(requests: list[BurpRequest]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for req in requests:
        parsed = urlparse(req.url)
        path = parsed.path
        key = f"{req.method}:{path}"
        if key in seen:
            continue
        seen.add(key)

        query_params = parse_qs(parsed.query)
        endpoints.append({
            "method": req.method,
            "path": path,
            "full_url": req.url,
            "params": list(query_params.keys()),
            "has_body": bool(req.body),
            "status": req.status,
        })

    return endpoints
