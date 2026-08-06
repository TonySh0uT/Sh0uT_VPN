import json
import os
import base64

# 1. Читаем базовый шаблон
with open('template.json', 'r', encoding='utf-8') as f:
    config = json.load(f)

servers = []
proxy_counter = 1
servers_dir = 'servers'

# 2. Собираем все конфиги серверов
if os.path.exists(servers_dir):
    for filename in os.listdir(servers_dir):
        if filename.endswith('.json'):
            with open(os.path.join(servers_dir, filename), 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Поддерживаем как один сервер в файле, так и массив серверов
                if isinstance(data, dict):
                    data = [data]

                for server in data:
                    # Прописываем теги (proxy-1, proxy-2), чтобы их подхватил балансировщик (selector: "proxy-")
                    server['tag'] = f"proxy-{proxy_counter}"
                    servers.append(server)
                    proxy_counter += 1

# 3. Вставляем серверы в начало блока outbounds
if 'outbounds' not in config:
    config['outbounds'] = []
config['outbounds'] = servers + config['outbounds']

# 4. Обновляем fallbackTag у балансировщика на первый доступный сервер
if servers and 'routing' in config and 'balancers' in config['routing']:
    for b in config['routing']['balancers']:
        if b.get('tag') == 'Balancer':
            b['fallbackTag'] = 'proxy-1'

# 5. Преобразуем в компактный JSON и кодируем в Base64 (стандарт подписок)
json_str = json.dumps(config, separators=(',', ':'))
b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

# 6. Сохраняем в папку public для отправки на GitHub Pages
os.makedirs('public', exist_ok=True)
with open('public/sub', 'w', encoding='utf-8') as f:
    f.write(b64_str)

print(f"Сборка завершена. Добавлено серверов: {len(servers)}")