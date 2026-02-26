# node-filter v2 - TSPU Check Edition

## 🆕 Что добавлено (из xraycheck)

### 1. **Strong Mode** (Строгий режим)
- **N запросов подряд** (по умолчанию 3) — все должны пройти успешно
- Имитирует поведение мобильных клиентов (SagerNet, sing-box, v2rayNG)
- Выявляет ноды, которые ТСПУ пропускает 1 раз, но блокирует последующие

```go
StrongAttempts = 3           // N запросов подряд
StrongMaxResponseTime = 3s   // Макс. время ответа (throttle detection)
StrongDelay = 500ms          // Пауза между запросами
```

### 2. **Stability Checks** (Проверка стабильности)
- Несколько циклов проверки с задержкой
- Выявляет вероятностные блокировки ТСПУ

```go
StabilityChecks = 2          // 2 цикла проверки
StabilityDelay = 2s          // Задержка между циклами
```

### 3. **HTTPS Check** (Как в мобильных клиентах)
- Проверка `https://www.gstatic.com/generate_204`
- Статус должен быть 204, тело — пустым
- HTTP может работать, HTTPS блокироваться ТСПУ

### 4. **Throttle Detection** (Обнаружение замедления)
- Если ответ > 3 секунд — вероятно ТСПУ throttle
- Нода с throttle практически непригодна

## 📊 Новые счётчики статистики

| Счётчик | Описание |
|---------|----------|
| `statsStrongFailed` | Не прошли N запросов подряд |
| `statsThrottled` | Обнаружен throttle (медленный ответ) |
| `statsStabilityFail` | Нестабильные (прошли не все циклы) |
| `statsHTTPSFailed` | Не прошли HTTPS проверку |

## 🚀 Запуск

```bash
# С флагами по умолчанию (strong=true, https=true)
./node-filter-v2 -input proxies.txt -whitelist whitelists.txt

# Отключить HTTPS проверку
./node-filter-v2 -input proxies.txt -https=false

# Отключить строгий режим (как старая версия)
./node-filter-v2 -input proxies.txt -strong=false

# Verbose режим
./node-filter-v2 -input proxies.txt -verbose
```

## 📁 Результаты

Вывод сохраняется в файлы с суффиксом `_v2`:
- `uf_v2.txt` — Ultra Fast
- `fast_v2.txt` — Fast
- `norm_v2.txt` — Normal

Это позволяет сравнивать с результатами старой версии.

## 🔬 Сравнение с v1

| Проверка | v1 (старая) | v2 (TSPU) |
|----------|-------------|-----------|
| HTTP проверка | 1 запрос | 1 запрос |
| Strong Mode | ❌ Нет | ✅ 3 запроса подряд |
| Stability | ❌ Нет | ✅ 2 цикла |
| HTTPS Check | ❌ Нет | ✅ gstatic/generate_204 |
| Throttle Detection | ❌ Нет | ✅ По времени ответа |
| Средняя задержка | ❌ Нет | ✅ В названии ноды |

## 💡 Почему это важно для ТСПУ

1. **Вероятностные блокировки** — ТСПУ может пропустить 1 запрос из 3
2. **Throttle** — ТСПУ замедляет, а не блокирует полностью
3. **HTTPS vs HTTP** — HTTP может работать, HTTPS блокироваться
4. **Мобильные клиенты** — делают именно такую проверку

---

*Версия создана на основе анализа репозитория xraycheck (WhitePrime)*
