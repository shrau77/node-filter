#!/bin/bash
# Скрипт сравнения результатов v1 vs v2

echo "=================================================="
echo "📊 СРАВНЕНИЕ РЕЗУЛЬТАТОВ: v1 (старая) vs v2 (TSPU)"
echo "=================================================="

# Проверяем наличие файлов
if [ ! -f "../uf.txt" ] && [ ! -f "../fast.txt" ] && [ ! -f "../norm.txt" ]; then
    echo "❌ Файлы v1 не найдены. Запустите сначала старую версию."
    exit 1
fi

if [ ! -f "uf_v2.txt" ] && [ ! -f "fast_v2.txt" ] && [ ! -f "norm_v2.txt" ]; then
    echo "❌ Файлы v2 не найдены. Запустите сначала новую версию."
    exit 1
fi

# Подсчёт строк
uf_v1=$(wc -l < ../uf.txt 2>/dev/null || echo 0)
fast_v1=$(wc -l < ../fast.txt 2>/dev/null || echo 0)
norm_v1=$(wc -l < ../norm.txt 2>/dev/null || echo 0)
total_v1=$((uf_v1 + fast_v1 + norm_v1))

uf_v2=$(wc -l < uf_v2.txt 2>/dev/null || echo 0)
fast_v2=$(wc -l < fast_v2.txt 2>/dev/null || echo 0)
norm_v2=$(wc -l < norm_v2.txt 2>/dev/null || echo 0)
total_v2=$((uf_v2 + fast_v2 + norm_v2))

# Вывод таблицы
echo ""
echo "┌─────────────────┬───────────┬───────────┬──────────┐"
echo "│ Категория       │    v1     │    v2     │  Разница │"
echo "├─────────────────┼───────────┼───────────┼──────────┤"
printf "│ 💎 Ultra Fast   │  %7d  │  %7d  │  %+6d  │\n" $uf_v1 $uf_v2 $((uf_v2 - uf_v1))
printf "│ ⚡ Fast         │  %7d  │  %7d  │  %+6d  │\n" $fast_v1 $fast_v2 $((fast_v2 - fast_v1))
printf "│ ✅ Normal       │  %7d  │  %7d  │  %+6d  │\n" $norm_v1 $norm_v2 $((norm_v2 - norm_v1))
echo "├─────────────────┼───────────┼───────────┼──────────┤"
printf "│ 📊 ИТОГО        │  %7d  │  %7d  │  %+6d  │\n" $total_v1 $total_v2 $((total_v2 - total_v1))
echo "└─────────────────┴───────────┴───────────┴──────────┘"

# Процент отсеянных
if [ $total_v1 -gt 0 ]; then
    filtered=$((total_v1 - total_v2))
    percent=$(echo "scale=1; $filtered * 100 / $total_v1" | bc)
    echo ""
    echo "📉 Отсеяно v2: $filtered нод ($percent%)"
fi

# Поиск нод, которые есть в v1, но нет в v2 (отсеяны ТСПУ-проверкой)
if [ -f "../uf.txt" ] && [ -f "uf_v2.txt" ]; then
    echo ""
    echo "🔍 Примеры нод, отсеянных v2 (TSPU check):"
    
    # Берём первые 5 нод из v1, которых нет в v2
    count=0
    while IFS= read -r line; do
        # Извлекаем адрес (до #)
        addr=$(echo "$line" | cut -d'#' -f1)
        
        # Ищем в v2
        if ! grep -q "$addr" uf_v2.txt fast_v2.txt norm_v2.txt 2>/dev/null; then
            echo "   ❌ $(echo "$line" | cut -c1-80)"
            ((count++))
            if [ $count -ge 5 ]; then
                break
            fi
        fi
    done < ../uf.txt
    
    if [ $count -eq 0 ]; then
        echo "   (все Ultra Fast из v1 прошли v2 проверку)"
    fi
fi

echo ""
echo "=================================================="
echo "📁 Файлы для сравнения:"
echo "   v1: ../uf.txt, ../fast.txt, ../norm.txt"
echo "   v2: uf_v2.txt, fast_v2.txt, norm_v2.txt"
echo "=================================================="
