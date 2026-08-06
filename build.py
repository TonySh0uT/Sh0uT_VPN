import json
import os
import base64
import urllib.parse

servers_dir = 'servers'
vless_links = []

if os.path.exists(servers_dir):
    for filename in os.listdir(servers_dir):
        if filename.endswith('.json'):
            with open(os.path.join(servers_dir, filename), 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)

                    items_to_process = []
                    if isinstance(data, dict) and 'outbounds' in data:
                        items_to_process = data['outbounds']
                    elif isinstance(data, list):
                        items_to_process = data
                    else:
                        items_to_process = [data]

                    # ИЩЕМ ТОЛЬКО ПЕРВЫЙ VLESS СЕРВЕР В ФАЙЛЕ
                    first_vless = None
                    for item in items_to_process:
                        if item.get('protocol') == 'vless':
                            first_vless = item
                            break # Нашли первый - останавливаем поиск

                    if first_vless:
                        vnext = first_vless['settings']['vnext'][0]
                        address = vnext['address']
                        port = vnext['port']
                        user_id = vnext['users'][0]['id']

                        stream = first_vless.get('streamSettings', {})
                        network = stream.get('network', 'tcp')
                        security = stream.get('security', 'none')

                        query_params = [f"type={network}", f"security={security}", "encryption=none"]

                        if security == 'tls':
                            tls = stream.get('tlsSettings', {})
                            if tls.get('serverName'):
                                query_params.append(f"sni={tls['serverName']}")
                            if tls.get('fingerprint'):
                                query_params.append(f"fp={tls['fingerprint']}")
                            if tls.get('alpn'):
                                query_params.append(f"alpn={urllib.parse.quote(','.join(tls['alpn']), safe='')}")

                        if network == 'ws':
                            ws = stream.get('wsSettings', {})
                            if ws.get('host'):
                                query_params.append(f"host={ws['host']}")
                            if ws.get('path'):
                                query_params.append(f"path={urllib.parse.quote(ws['path'], safe='')}")

                        # Называем сервер именем файла (например: server_germany)
                        server_name = filename.replace('.json', '')
                        query_string = "&".join(query_params)
                        link = f"vless://{user_id}@{address}:{port}?{query_string}#{urllib.parse.quote(server_name)}"

                        vless_links.append(link)

                except Exception as e:
                    print(f"Ошибка при обработке файла {filename}: {e}")

# Сохраняем результат
os.makedirs('files', exist_ok=True)
links_str = "\n".join(vless_links)
b64_links = base64.b64encode(links_str.encode('utf-8')).decode('utf-8')

with open('files/sub', 'w', encoding='utf-8') as f:
    f.write(b64_links)

print(f"Сборка завершена! Сгенерировано ссылок: {len(vless_links)}")