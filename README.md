# Honeypot Anti-Spam CAPTCHA for OpenCart 3 / LiveStore

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/damatveev/Honeypot/releases)
[![OpenCart](https://img.shields.io/badge/OpenCart-3.x-blue.svg)](https://www.opencart.com/)
[![PHP](https://img.shields.io/badge/PHP-7.2--8.1-777bb4.svg)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Honeypot Anti-Spam CAPTCHA** — дополнительная антибот-защита форм OpenCart 3.x / LiveStore. Версия 1.2.0 усиливает регистрацию несколькими независимыми проверками и может автоматически подключать **Yandex SmartCaptcha** с уже существующими API-ключами стандартного модуля Yandex CAPTCHA.

English: Honeypot Anti-Spam CAPTCHA is an OpenCart 3.x / LiveStore extension that adds layered anti-bot protection with honeypot fields, JavaScript verification, expiring form tokens, rate limiting and optional Yandex SmartCaptcha reuse.

## Версия 1.2.0

На регистрации одновременно могут использоваться:

- два скрытых honeypot-поля;
- одноразовый session-token;
- контроль срока жизни токена;
- проверка User-Agent между открытием и отправкой формы;
- JavaScript-проверка;
- минимальное время заполнения;
- rate limit по IP/route;
- Yandex SmartCaptcha.

Если стандартный модуль **Yandex CAPTCHA** включён и в нём уже заданы `site key` и `secret`, Honeypot использует эти настройки автоматически. Повторно вводить API-ключи в Honeypot не требуется.

## Yandex SmartCaptcha

Для усиленной защиты регистрации Honeypot 1.2.0 проверяет наличие стандартного модуля Yandex CAPTCHA. Если он включён и настроен, на странице регистрации добавляется Yandex SmartCaptcha, если она ещё не выведена основной CAPTCHA.

Если Yandex уже выбрана основной CAPTCHA для регистрации, Honeypot не выводит второй визуальный виджет и работает как дополнительный скрытый антибот-слой.

## Возможности

- два динамических honeypot-поля без `display:none`;
- случайные имена ловушек для каждой формы;
- одноразовый токен формы;
- ограниченный срок жизни токена;
- привязка токена к User-Agent;
- JavaScript-проверка;
- контроль минимального времени заполнения;
- rate limit и временная блокировка по IP/route;
- дополнительная Yandex SmartCaptcha на регистрации;
- совместная работа с Google / Yandex / Basic CAPTCHA;
- журнал e-mail, имени, IP, User-Agent, route, причины и времени обнаружения;
- фильтры и статистика в административной панели;
- настраиваемый срок хранения журнала;
- QR-код и ссылка для поддержки разработки;
- OCMOD + стандартный механизм CAPTCHA OpenCart;
- VQMod и OpenCart Events не требуются.

Пароли и содержимое сообщений модуль не сохраняет.

## Причины блокировки в журнале

`honeypot`, `too_fast`, `invalid_token`, `missing_session`, `expired_token`, `client_mismatch`, `missing_trap`, `js_check`, `rate_limit`, `yandex_failed`.

## Установка

1. Скачайте `dist/honeypot_antispam_captcha_v1.2.0.ocmod.zip`.
2. Откройте `Дополнения → Установка дополнений` и загрузите ZIP.
3. Перейдите в `Дополнения → Дополнения` → тип `CAPTCHA`.
4. Установите и откройте **Honeypot Anti-Spam**.
5. Включите расширение.
6. Откройте `Дополнения → Модификаторы` и обновите кеш модификаций.
7. Для Yandex SmartCaptcha убедитесь, что стандартный модуль Yandex CAPTCHA включён и в нём заполнены site key и secret.
8. Проверьте регистрацию и журнал блокировок.

## Рекомендуемые параметры

Для регистрации рекомендуются начальные значения:

- минимальное время заполнения: 5 секунд;
- JavaScript-проверка: включена;
- срок жизни токена: 1800 секунд;
- rate limit: включён;
- лимит: 6 попыток;
- окно: 900 секунд;
- блокировка: 1800 секунд.

При необходимости значения можно скорректировать под фактический трафик магазина.

## Совместимость

- OpenCart 3.x;
- LiveStore 3.x;
- PHP 7.2–8.1;
- рекомендуемый диапазон PHP 7.4–8.1;
- OCMOD: да;
- VQMod: нет;
- Events: нет.

Сторонние темы, OCMOD и изменённые контроллеры могут влиять на точки интеграции. После установки необходимо проверить регистрацию на конкретной сборке магазина.

## Скачать

Актуальные версии публикуются в [GitHub Releases](https://github.com/damatveev/Honeypot/releases). Готовый пакет текущей версии также находится в каталоге [`dist`](https://github.com/damatveev/Honeypot/tree/main/dist).

## Keywords

OpenCart, OpenCart 3, LiveStore, ocStore, honeypot, anti-spam, antispam, spam protection, CAPTCHA, Yandex SmartCaptcha, bot protection, form security, invisible captcha, OCMOD, PHP, ecommerce, OpenCart extension, OpenCart module, защита от спама, защита от ботов.

## Поддержка проекта / Donate

Если модуль оказался полезен, разработку можно поддержать:

https://boosty.to/matveevd/donate

QR-код для поддержки проекта включён в административный интерфейс модуля.

## Автор

**Dmitry Matveev**  
E-mail: d.a.matveev@gmail.com

## Лицензия

Распространяется по лицензии [MIT](LICENSE).