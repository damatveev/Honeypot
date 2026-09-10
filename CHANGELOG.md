# Changelog

## 1.2.0
- Усилена защита регистрации независимо от списка страниц основной CAPTCHA.
- Добавлены два honeypot-поля, JavaScript-проверка и привязка токена к User-Agent.
- Минимальное время заполнения по умолчанию увеличено до 5 секунд.
- Добавлен срок жизни токена формы.
- Добавлен rate limit по IP/route с временной блокировкой.
- Добавлены новые причины блокировки в журнале: missing_session, expired_token, client_mismatch, missing_trap, js_check, rate_limit, yandex_failed.
- Для регистрации автоматически подключается Yandex SmartCaptcha, если стандартный модуль Yandex CAPTCHA включён и в нём уже настроены site key и secret.
- Используются существующие настройки Yandex CAPTCHA; отдельные API-ключи в Honeypot вводить не требуется.

## 1.1.0
- Совместная работа с Google/Yandex/Basic CAPTCHA.
- Honeypot не требуется выбирать основной CAPTCHA.
- QR-код Boosty и ссылка благодарности в админке.
- README, инструкция по распространению и готовый dist-пакет.

## 1.0.0
- Honeypot-ловушка.
- Проверка времени заполнения.
- Журнал e-mail/IP/User-Agent.
- Статистика и фильтры.
