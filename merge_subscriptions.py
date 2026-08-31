import base64
import json
import os
import re
import sys
from copy import deepcopy
from urllib.parse import parse_qs, unquote


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def decode_base64(data: str) -> str:
    data = data.strip()
    data = data.lstrip("\ufeff")
    data = re.sub(r"\s+", "", data)

    padding = "=" * (-len(data) % 4)

    try:
        decoded = base64.b64decode(
            data + padding
        )
        return decoded.decode("utf-8")

    except Exception as exc:
        raise RuntimeError(
            f"Не удалось декодировать Base64: {exc}"
        )


def parse_vless_uri(uri: str, index: int) -> dict:
    """
    Convert vless:// URI into Xray outbound.
    """

    uri = uri.strip()

    if not uri.lower().startswith("vless://"):
        raise ValueError(
            f"Не VLESS URI: {uri[:50]}"
        )

    raw = uri[8:]

    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        name = unquote(fragment)
    else:
        name = f"Server {index}"

    if "?" in raw:
        address_part, query_string = raw.split(
            "?", 1
        )
    else:
        address_part = raw
        query_string = ""

    if "@" not in address_part:
        raise ValueError(
            f"Некорректный VLESS URI: {uri}"
        )

    user_uuid, server = address_part.split(
        "@", 1
    )

    if server.startswith("["):
        match = re.match(
            r"^\[(.+)]:(\d+)$",
            server
        )

        if not match:
            raise ValueError(
                f"Некорректный IPv6: {server}"
            )

        address = match.group(1)
        port = int(match.group(2))

    else:
        address, port = server.rsplit(
            ":",
            1
        )
        port = int(port)

    params = parse_qs(
        query_string,
        keep_blank_values=True
    )

    def get(name, default=None):
        values = params.get(name)
        return values[0] if values else default

    network = get("type", "tcp")
    security = get("security", "none")

    outbound = {
        "tag": "proxy",
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

    # WebSocket
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

        stream["wsSettings"] = (
            ws_settings
        )

    # TCP
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

    # gRPC
    elif network == "grpc":

        grpc_settings = {}

        service_name = get(
            "serviceName"
        )

        if service_name:
            grpc_settings[
                "serviceName"
            ] = service_name

        stream["grpcSettings"] = (
            grpc_settings
        )

    # HTTP
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

        stream["httpSettings"] = (
            http_settings
        )

    # HTTP Upgrade
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

    # XHTTP
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

        stream["xhttpSettings"] = (
            settings
        )

    # TLS
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

    # REALITY
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

    return {
        "outbound": outbound,
        "name": name
    }


def parse_vpn2(raw: str) -> list[dict]:
    """
    VPN2 is Base64 containing one VLESS URI per line.
    """

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

            parsed = parse_vless_uri(
                line,
                len(result) + 1
            )

            result.append(parsed)

        except Exception as exc:

            print(
                f"WARNING: "
                f"не удалось разобрать VPN2 URI: "
                f"{exc}",
                file=sys.stderr
            )

    return result


def create_vpn2_profile(
    template: dict,
    vpn2_server: dict,
    index: int
) -> dict:
    """
    Create a separate profile for one VPN2 server,
    using VPN1 profile as structural template.
    """

    profile = deepcopy(template)

    name = vpn2_server["name"]

    profile["remarks"] = (
        f"VPN2 | {name}"
    )

    outbounds = profile.get(
        "outbounds"
    )

    if not isinstance(
        outbounds,
        list
    ):
        outbounds = []

    # Keep useful technical outbounds.
    technical = []

    for outbound in outbounds:

        if not isinstance(
            outbound,
            dict
        ):
            continue

        tag = outbound.get(
            "tag"
        )

        if tag in {
            "block",
            "direct",
            "direct-fragment"
        }:
            technical.append(
                outbound
            )

    # The VPN2 server becomes "proxy".
    main_outbound = deepcopy(
        vpn2_server["outbound"]
    )

    main_outbound["tag"] = "proxy"

    profile["outbounds"] = [
        main_outbound,
        *technical
    ]

    # ---------------------------------
    # Make routing point directly
    # to proxy.
    # ---------------------------------

    routing = profile.get(
        "routing"
    )

    if isinstance(
        routing,
        dict
    ):

        balancers = routing.get(
            "balancers"
        )

        # A single VPN2 server does not
        # need the VPN1 balancer.
        if isinstance(
            balancers,
            list
        ):
            routing["balancers"] = []

        rules = routing.get(
            "rules"
        )

        if isinstance(
            rules,
            list
        ):

            for rule in rules:

                if not isinstance(
                    rule,
                    dict
                ):
                    continue

                if (
                    "balancerTag"
                    in rule
                ):
                    rule.pop(
                        "balancerTag",
                        None
                    )
                    rule[
                        "outboundTag"
                    ] = "proxy"

                elif (
                    rule.get(
                        "outboundTag"
                    )
                    not in {
                        "direct",
                        "block",
                        "direct-fragment",
                        "proxy"
                    }
                ):
                    rule[
                        "outboundTag"
                    ] = "proxy"

    # Observatory for one node.
    observatory = profile.get(
        "observatory"
    )

    if isinstance(
        observatory,
        dict
    ):
        observatory[
            "subjectSelector"
        ] = ["proxy"]

    return profile


def prefix_vpn1(profile: dict):
    """
    Add VPN1 prefix only to profile name.
    Everything else remains untouched.
    """

    old_name = profile.get(
        "remarks",
        ""
    )

    profile["remarks"] = (
        f"VPN1 | {old_name}"
        if old_name
        else "VPN1"
    )


def main():

    vpn1_file = os.environ.get(
        "VPN1_FILE",
        "files/vpn1"
    )

    vpn2_file = os.environ.get(
        "VPN2_FILE",
        "files/vpn2"
    )

    output_file = os.environ.get(
        "OUTPUT_FILE",
        "files/external_sub"
    )

    # =========================
    # VPN1
    # =========================

    vpn1 = load_json(
        vpn1_file
    )

    if not isinstance(
        vpn1,
        list
    ):
        vpn1 = [vpn1]

    if not vpn1:
        raise RuntimeError(
            "VPN1 не содержит профилей"
        )

    print(
        f"VPN1: найдено "
        f"{len(vpn1)} профилей"
    )

    # Keep VPN1 intact except remarks.
    vpn1_profiles = []

    for profile in vpn1:

        if not isinstance(
            profile,
            dict
        ):
            continue

        profile = deepcopy(
            profile
        )

        prefix_vpn1(
            profile
        )

        vpn1_profiles.append(
            profile
        )

    # =========================
    # VPN2
    # =========================

    with open(
        vpn2_file,
        "r",
        encoding="utf-8"
    ) as f:

        vpn2_raw = f.read()

    vpn2_servers = parse_vpn2(
        vpn2_raw
    )

    if not vpn2_servers:
        raise RuntimeError(
            "VPN2 не содержит VLESS серверов"
        )

    print(
        f"VPN2: найдено "
        f"{len(vpn2_servers)} серверов"
    )

    # =========================
    # VPN2 profiles
    # =========================

    # Use first VPN1 profile as
    # structural template.
    template = vpn1_profiles[0]

    vpn2_profiles = []

    for index, server in enumerate(
        vpn2_servers,
        start=1
    ):

        profile = create_vpn2_profile(
            template,
            server,
            index
        )

        vpn2_profiles.append(
            profile
        )

    print(
        f"VPN2: создано "
        f"{len(vpn2_profiles)} профилей"
    )

    # =========================
    # Merge
    # =========================

    merged = (
        vpn1_profiles +
        vpn2_profiles
    )

    print(
        f"Итого профилей: "
        f"{len(merged)}"
    )

    # =========================
    # Save
    # =========================

    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        json.dump(
            merged,
            f,
            ensure_ascii=False,
            separators=(",", ":")
        )

    print(
        f"Готово: {output_file}"
    )


if __name__ == "__main__":
    main()