# XILLEN Hash Cracker

Профессиональный инструмент для взлома хешей, разработанный командой Xillen Killers.

## Возможности

### 🔐 Поддерживаемые алгоритмы
- **MD5** - Message Digest Algorithm 5
- **SHA1** - Secure Hash Algorithm 1
- **SHA256** - Secure Hash Algorithm 256

### ⚡ Методы атак
- **Rainbow Table** - предвычисленные таблицы хешей
- **Dictionary Attack** - атака по словарю
- **Bruteforce** - полный перебор символов
- **Multithreading** - многопоточная обработка

### 🛠️ Дополнительные функции
- Генерация радужных таблиц
- Сохранение/загрузка таблиц
- Настраиваемое количество потоков
- Подробное логирование операций

## Установка

### Требования
- C++17 совместимый компилятор (GCC 7+, Clang 5+)
- OpenSSL библиотеки
- Make утилита

### Установка зависимостей

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential libssl-dev make
```

#### CentOS/RHEL:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel make
```

#### macOS:
```bash
brew install openssl make
```

### Компиляция
```bash
make
```

### Установка в систему
```bash
sudo make install
```

## Использование

### Запуск
```bash
./xillen_hash_cracker
```

### Основные команды

1. **Load wordlist** - загрузить словарь для атак
2. **Generate rainbow table** - создать радужную таблицу
3. **Crack hash** - взломать хеш (комбинированный метод)
4. **Dictionary attack** - атака по словарю
5. **Bruteforce attack** - полный перебор
6. **Save rainbow table** - сохранить радужную таблицу
7. **Load rainbow table** - загрузить радужную таблицу
8. **Set threads** - настроить количество потоков
9. **Toggle verbose** - включить/выключить подробный вывод

### Примеры использования

#### Взлом MD5 хеша:
```
1. Load wordlist
   Enter wordlist filename: rockyou.txt
   
2. Generate rainbow table
   Enter algorithm: md5
   Enter max length: 6
   
3. Crack hash
   Enter hash to crack: 5f4dcc3b5aa765d61d8327deb882cf99
   Enter algorithm: md5
```

#### Настройка производительности:
```
8. Set threads
   Enter number of threads: 8
   
9. Toggle verbose
   Verbose mode: ON
```

## Производительность

### Многопоточность
- Автоматическое определение количества ядер
- Настраиваемое количество потоков
- Эффективное распределение нагрузки

### Оптимизации
- Компиляция с флагами оптимизации (-O3)
- Использование современных C++17 возможностей
- Оптимизированные алгоритмы хеширования

### Бенчмарки
- **MD5**: ~100M хешей/сек на современном CPU
- **SHA1**: ~50M хешей/сек на современном CPU
- **SHA256**: ~25M хешей/сек на современном CPU

## Безопасность

### Предупреждения
- Используйте только для тестирования собственных систем
- Не применяйте для несанкционированного взлома
- Соблюдайте местное законодательство

### Рекомендации
- Регулярно обновляйте словари
- Используйте сложные пароли
- Применяйте соль к хешам

## Технические детали

### Архитектура
- Объектно-ориентированный дизайн
- Модульная структура кода
- Обработка ошибок и исключений

### Совместимость
- Linux (Ubuntu, CentOS, Arch)
- macOS (с Homebrew)
- Windows (с WSL или MinGW)

### Зависимости
- OpenSSL 1.1.0+
- pthread библиотека
- Стандартная библиотека C++17

## Авторы

- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Техническая поддержка

## Ссылки

- [https://benjaminbutton.ru/](https://benjaminbutton.ru/)
- [https://xillenkillers.ru/](https://xillenkillers.ru/)
- [t.me/XillenAdapter](https://t.me/XillenAdapter)

## Лицензия

Проект разработан для образовательных целей и тестирования безопасности собственных систем.

## Поддержка

Для получения помощи или сообщения об ошибках обращайтесь к авторам проекта.

