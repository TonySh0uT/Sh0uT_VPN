import base64
import json
import os
import re
import sys


def load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def decode_base64_to_text(data: str) -> str:
    data = data.strip()
    data = data.lstrip("\ufeff")

    data = re.sub(r"\s+", "", data)

    try:
        decoded = base64.b64decode(
            data,
            validate=True
        )
        return decoded.decode("utf-8")

    except Exception as exc:
        raise RuntimeError(
            f"Не удалось декодировать Base64: {exc}"
        )


def load_profiles(path: str):
    """
    Load subscription in either:
    - JSON object
    - JSON array
    - Base64 encoded JSON
    """

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()

    if not raw:
        raise RuntimeError(
            f"Файл {path} пустой"
        )

    # -------------------------
    # Try plain JSON first.
    # -------------------------

    try:
        data = json.loads(raw)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    # -------------------------
    # Try Base64.
    # -------------------------

    try:
        decoded = decode_base64_to_text(raw)

        data = json.loads(decoded)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    except Exception as exc:
        raise RuntimeError(
            f"Не удалось распознать подписку "
            f"{path}: {exc}"
        )

    raise RuntimeError(
        f"Неизвестный формат подписки: {path}"
    )


def add_source_to_remarks(
    profile: dict,
    source: str
):
    """
    Prefix profile remarks with VPN1/VPN2.
    """

    old_remarks = profile.get(
        "remarks",
        ""
    )

    if old_remarks:
        profile["remarks"] = (
            f"{source} | {old_remarks}"
        )
    else:
        profile["remarks"] = source


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

    # -------------------------
    # Load VPN1
    # -------------------------

    vpn1_profiles = load_profiles(
        vpn1_file
    )

    if not vpn1_profiles:
        raise RuntimeError(
            "VPN1 не содержит профилей"
        )

    print(
        f"VPN1: найдено "
        f"{len(vpn1_profiles)} профилей"
    )

    # -------------------------
    # Load VPN2
    # -------------------------

    vpn2_profiles = load_profiles(
        vpn2_file
    )

    if not vpn2_profiles:
        raise RuntimeError(
            "VPN2 не содержит профилей"
        )

    print(
        f"VPN2: найдено "
        f"{len(vpn2_profiles)} профилей"
    )

    # -------------------------
    # Add source names
    # -------------------------

    for profile in vpn1_profiles:

        if not isinstance(profile, dict):
            continue

        add_source_to_remarks(
            profile,
            "VPN1"
        )

    for profile in vpn2_profiles:

        if not isinstance(profile, dict):
            continue

        add_source_to_remarks(
            profile,
            "VPN2"
        )

    # -------------------------
    # Merge profiles
    # -------------------------

    merged = (
        vpn1_profiles +
        vpn2_profiles
    )

    print(
        f"Итого профилей: "
        f"{len(merged)}"
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