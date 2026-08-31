import base64
import json
import os
import re
import sys
from copy import deepcopy
from urllib.parse import parse_qs, unquote


def decode_base64(data: str) -> str:
    """
    Decode standard or URL-safe Base64.

    The source may contain:
    - spaces/newlines
    - BOM
    - accidental Unicode characters
    """

    # Remove all whitespace.
    data = re.sub(r"\s+", "", data.strip())

    # Base64 itself may contain only ASCII characters.
    # Remove anything that cannot belong to Base64.
    data = re.sub(
        r"[^A-Za-z0-9+/=_-]",
        "",
        data
    )

    # Try standard Base64.
    padding = "=" * (-len(data) % 4)

    try:
        decoded = base64.b64decode(
            data + padding,
            validate=False
        )

        return decoded.decode(
            "utf-8"
        )

    except Exception:
        pass

    # Try URL-safe Base64.
    try:
        decoded = base64.urlsafe_b64decode(
            data + padding
        )

        return decoded.decode(
            "utf-8"
        )

    except Exception as exc:
        raise RuntimeError(
            f"Не удалось декодировать VPN1: {exc}"
        )


def parse_vless_uri(uri: str, index: int) -> dict:
    """
    Convert a VLESS URI into an Xray outbound.
    """

    raw = uri[len("vless://"):]

    # Server name after #
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        name = unquote(fragment)
    else:
        name = f"Server {index}"

    # Query parameters
    if "?" in raw:
        address_part, query_string = raw.split("?", 1)
    else:
        address_part = raw
        query_string = ""

    if "@" not in address_part:
        raise ValueError(
            f"Некорректный VLESS URI: {uri}"
        )

    user_uuid, server = address_part.split("@", 1)

    # IPv6
    if server.startswith("["):
        match = re.match(
            r"^\[(.+)]:(\d+)$",
            server
        )

        if not match:
            raise ValueError(
                f"Некорректный IPv6 адрес: {server}"
            )

        address = match.group(1)
        port = int(match.group(2))

    else:
        address, port = server.rsplit(":", 1)
        port = int(port)

    params = parse_qs(
        query_string,
        keep_blank_values=True
    )

    def get(name, default=None):
        values = params.get(name)
        return values[0] if values else default

    network = get(
        "type",
        get("network", "tcp")
    )

    security = get(
        "security",
        "none"
    )

    outbound = {
        "tag": f"VPN1 | {name}",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": user_uuid,
                            "encryption": get(
                                "encryption",
                                "none"
                            ),
                            "flow": get(
                                "flow",
                                ""
                            )
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": network
        }
    }

    stream = outbound["streamSettings"]

    # -------------------------
    # WebSocket
    # -------------------------

    if network == "ws":
        ws_settings = {}

        path = get("path")
        host = get("host")

        if path:
            ws_settings["path"] = path

        if host:
            ws_settings["headers"] = {
                "Host": host
            }

        stream["wsSettings"] = ws_settings

    # -------------------------
    # TCP
    # -------------------------

    elif network == "tcp":
        header_type = get(
            "headerType"
        )

        if header_type:
            stream["tcpSettings"] = {
                "header": {
                    "type": header_type
                }
            }

    # -------------------------
    # gRPC
    # -------------------------

    elif network == "grpc":
        grpc_settings = {}

        service_name = get(
            "serviceName"
        )

        if service_name:
            grpc_settings[
                "serviceName"
            ] = service_name

        stream[
            "grpcSettings"
        ] = grpc_settings

    # -------------------------
    # HTTP
    # -------------------------

    elif network == "http":
        http_settings = {}

        path = get("path")
        host = get("host")

        if path:
            http_settings["path"] = path

        if host:
            http_settings["host"] = [
                host
            ]

        stream[
            "httpSettings"
        ] = http_settings

    # -------------------------
    # HTTP Upgrade
    # -------------------------

    elif network == "httpupgrade":
        settings = {}

        path = get("path")
        host = get("host")

        if path:
            settings["path"] = path

        if host:
            settings["host"] = host

        stream[
            "httpupgradeSettings"
        ] = settings

    # -------------------------
    # XHTTP
    # -------------------------

    elif network == "xhttp":
        settings = {}

        path = get("path")
        host = get("host")
        mode = get("mode")

        if path:
            settings["path"] = path

        if host:
            settings["host"] = host

        if mode:
            settings["mode"] = mode

        stream[
            "xhttpSettings"
        ] = settings

    # -------------------------
    # TLS
    # -------------------------

    if security == "tls":
        tls_settings = {}

        sni = get("sni")
        fingerprint = get("fp")
        alpn = get("alpn")

        if sni:
            tls_settings[
                "serverName"
            ] = sni

        if fingerprint:
            tls_settings[
                "fingerprint"
            ] = fingerprint

        if alpn:
            tls_settings["alpn"] = (
                alpn.split(",")
            )

        stream["security"] = "tls"
        stream["tlsSettings"] = (
            tls_settings
        )

    # -------------------------
    # REALITY
    # -------------------------

    elif security == "reality":
        reality_settings = {
            "show": False
        }

        sni = get("sni")
        fingerprint = get("fp")
        public_key = get("pbk")
        short_id = get("sid")

        if sni:
            reality_settings[
                "serverName"
            ] = sni

        if fingerprint:
            reality_settings[
                "fingerprint"
            ] = fingerprint

        if public_key:
            reality_settings[
                "publicKey"
            ] = public_key

        if short_id:
            reality_settings[
                "shortId"
            ] = short_id

        stream["security"] = "reality"
        stream[
            "realitySettings"
        ] = reality_settings

    return outbound


def parse_vpn1(raw: str) -> list[dict]:
    """Read VPN1 Base64 subscription."""

    decoded = decode_base64(raw)

    result = []

    for line in decoded.splitlines():

        line = line.strip()

        if not line:
            continue

        if not line.lower().startswith(
            "vless://"
        ):
            continue

        try:

            outbound = parse_vless_uri(
                line,
                len(result) + 1
            )

            result.append(outbound)

        except Exception as exc:

            print(
                f"WARNING: VPN1: "
                f"не удалось разобрать URI: "
                f"{exc}",
                file=sys.stderr
            )

    return result


def add_vpn1_to_profile(
    profile: dict,
    vpn1_outbounds: list[dict]
) -> int:

    outbounds = profile.get(
        "outbounds"
    )

    if not isinstance(
        outbounds,
        list
    ):
        return 0

    existing_tags = {
        item.get("tag")
        for item in outbounds
        if isinstance(item, dict)
    }

    added = 0

    for outbound in vpn1_outbounds:

        new_outbound = deepcopy(
            outbound
        )

        tag = new_outbound.get(
            "tag"
        )

        if not tag:
            continue

        if tag in existing_tags:
            continue

        # Insert before technical outbounds.
        insert_position = len(
            outbounds
        )

        for i, existing in enumerate(
            outbounds
        ):

            if not isinstance(
                existing,
                dict
            ):
                continue

            existing_tag = existing.get(
                "tag"
            )

            if existing_tag in {
                "block",
                "direct",
                "direct-fragment"
            }:
                insert_position = i
                break

        outbounds.insert(
            insert_position,
            new_outbound
        )

        existing_tags.add(tag)
        added += 1

    # ----------------------------------
    # Add VPN1 prefix to existing
    # Balancer.
    # ----------------------------------

    routing = profile.get(
        "routing"
    )

    if not isinstance(
        routing,
        dict
    ):
        return added

    balancers = routing.get(
        "balancers"
    )

    if not isinstance(
        balancers,
        list
    ):
        return added

    for balancer in balancers:

        if not isinstance(
            balancer,
            dict
        ):
            continue

        if balancer.get(
            "tag"
        ) != "Balancer":
            continue

        selectors = balancer.setdefault(
            "selector",
            []
        )

        if not isinstance(
            selectors,
            list
        ):
            selectors = []
            balancer["selector"] = (
                selectors
            )

        if "VPN1 | " not in selectors:
            selectors.append(
                "VPN1 | "
            )

    return added


def main():

    source1_file = os.environ.get(
        "SOURCE1_FILE",
        "files/vpn1"
    )

    source2_file = os.environ.get(
        "SOURCE2_FILE",
        "files/vpn2"
    )

    output_file = os.environ.get(
        "OUTPUT_FILE",
        "files/external_sub"
    )

    # -------------------------
    # Load VPN1
    # -------------------------

    with open(
        source1_file,
        "r",
        encoding="utf-8"
    ) as f:

        vpn1_raw = f.read()

    vpn1_outbounds = parse_vpn1(
        vpn1_raw
    )

    if not vpn1_outbounds:
        raise RuntimeError(
            "VPN1 не содержит VLESS-серверов"
        )

    print(
        f"VPN1: найдено "
        f"{len(vpn1_outbounds)} серверов"
    )

    # -------------------------
    # Load VPN2
    # -------------------------

    with open(
        source2_file,
        "r",
        encoding="utf-8"
    ) as f:

        vpn2_raw = f.read()

    try:
        vpn2 = json.loads(
            vpn2_raw
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"VPN2 содержит "
            f"некорректный JSON: {exc}"
        )

    if isinstance(
        vpn2,
        list
    ):
        profiles = vpn2
        was_list = True

    elif isinstance(
        vpn2,
        dict
    ):
        profiles = [vpn2]
        was_list = False

    else:
        raise RuntimeError(
            "Корень VPN2 должен "
            "быть JSON object или array"
        )

    # -------------------------
    # Merge
    # -------------------------

    total_added = 0

    for index, profile in enumerate(
        profiles,
        start=1
    ):

        if not isinstance(
            profile,
            dict
        ):
            continue

        added = add_vpn1_to_profile(
            profile,
            vpn1_outbounds
        )

        total_added += added

        print(
            f"Профиль #{index}: "
            f"добавлено {added} "
            f"серверов VPN1"
        )

    if total_added == 0:
        raise RuntimeError(
            "Не удалось добавить "
            "серверы VPN1"
        )

    # -------------------------
    # Preserve original root type
    # -------------------------

    result = (
        profiles
        if was_list
        else profiles[0]
    )

    # -------------------------
    # Save
    # -------------------------

    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        json.dump(
            result,
            f,
            ensure_ascii=False,
            separators=(",", ":")
        )

    print(
        f"Готово: {output_file}"
    )

    print(
        f"Всего добавлено "
        f"VPN1 серверов: "
        f"{total_added}"
    )


if __name__ == "__main__":
    main()