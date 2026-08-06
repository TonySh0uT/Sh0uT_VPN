import json
import os
import base64

# 1. Читаем базовый шаблон
with open('template.json', 'r', encoding='utf-8') as f:
    config = json.load(f)

servers = []
proxy_counter = 1
servers_dir = 'servers'

# 2. Умный поиск серверов
if os.path.exists(servers_dir):
    for filename in os.listdir(servers_dir):
        if filename.endswith('.json'):
            with open(os.path.join(servers_dir, filename), 'r', encoding='utf-8') as f:
                data = json.load(f)

                items_to_process = []

                # Если это полный конфиг (как happ.txt), берем только массив outbounds
                if isinstance(data, dict) and 'outbounds' in data:
                    items_to_process = data['outbounds']
                # Если это массив серверов
                elif isinstance(data, list):
                    items_to_process = data
                # Если это одиночный сервер
                else:
                    items_to_process = [data]

                for item in items_to_process:
                    # Пропускаем технические подключения (direct, block, dns), берем только прокси
                    protocol = item.get('protocol', '')
                    if protocol in ['freedom', 'blackhole', 'dns']:
                        continue

                    # Прописываем правильный тег для балансировщика
                    item['tag'] = f"proxy-{proxy_counter}"
                    servers.append(item)
                    proxy_counter += 1

# 3. Вставляем найденные серверы в начало блока outbounds шаблона
if 'outbounds' not in config:
    config['outbounds'] = []
config['outbounds'] = servers + config['outbounds']

# 4. Обновляем fallbackTag у балансировщика на первый доступный сервер
if servers and 'routing' in config and 'balancers' in config['routing']:
    for b in config['routing']['balancers']:
        if b.get('tag') == 'Balancer':
            b['fallbackTag'] = 'proxy-1'

# 5. Собираем и кодируем
json_str = json.dumps(config, separators=(',', ':'))
b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

# 6. Сохраняем результат
os.makedirs('public', exist_ok=True)
with open('public/sub', 'w', encoding='utf-8') as f:
    f.write(b64_str)

print(f"Сборка завершена. Успешно извлечено и добавлено серверов: {len(servers)}")