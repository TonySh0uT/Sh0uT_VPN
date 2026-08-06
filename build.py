import json
import os
import base64
import urllib.parse

servers_dir = 'servers'
vless_links = []
proxy_counter = 1

if os.path.exists(servers_dir):
    for filename in os.listdir(servers_dir):
        if filename.endswith('.json'):
            with open(os.path.join(servers_dir, filename), 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)

                    # Поддержка разных форматов (один сервер, массив или выгрузка из outbounds)
                    items_to_process = []
                    if isinstance(data, dict) and 'outbounds' in data:
                        items_to_process = data['outbounds']
                    elif isinstance(data, list):
                        items_to_process = data
                    else:
                        items_to_process = [data]

                    for item in items_to_process:
                        if item.get('protocol') != 'vless':
                            continue

                        # Извлекаем базовые данные
                        vnext = item['settings']['vnext'][0]
                        address = vnext['address']
                        port = vnext['port']
                        user_id = vnext['users'][0]['id']

                        # Извлекаем настройки сети
                        stream = item.get('streamSettings', {})
                        network = stream.get('network', 'tcp')
                        security = stream.get('security', 'none')

                        query_params = [f"type={network}", f"security={security}", "encryption=none"]

                        # Настройки TLS
                        if security == 'tls':
                            tls = stream.get('tlsSettings', {})
                            if tls.get('serverName'):
                                query_params.append(f"sni={tls['serverName']}")
                            if tls.get('fingerprint'):
                                query_params.append(f"fp={tls['fingerprint']}")
                            if tls.get('alpn'):
                                query_params.append(f"alpn={urllib.parse.quote(','.join(tls['alpn']), safe='')}")

                        # Настройки WebSocket
                        if network == 'ws':
                            ws = stream.get('wsSettings', {})
                            if ws.get('host'):
                                query_params.append(f"host={ws['host']}")
                            if ws.get('path'):
                                query_params.append(f"path={urllib.parse.quote(ws['path'], safe='')}")

                        # Формируем итоговую ссылку
                        remark = f"Server-{proxy_counter} ({filename.replace('.json', '')})"
                        query_string = "&".join(query_params)
                        link = f"vless://{user_id}@{address}:{port}?{query_string}#{urllib.parse.quote(remark)}"

                        vless_links.append(link)
                        proxy_counter += 1

                except Exception as e:
                    print(f"Ошибка при обработке файла {filename}: {e}")

# Сохраняем результат в Base64
os.makedirs('files', exist_ok=True)
links_str = "\n".join(vless_links)
b64_links = base64.b64encode(links_str.encode('utf-8')).decode('utf-8')

with open('files/sub', 'w', encoding='utf-8') as f:
    f.write(b64_links)

print(f"Сборка завершена! Сгенерировано ссылок VLESS: {len(vless_links)}")