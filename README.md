# Honeypot Anti-Spam CAPTCHA for OpenCart 3 / LiveStore

[![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)](https://github.com/damatveev/Honeypot/releases)
[![OpenCart](https://img.shields.io/badge/OpenCart-3.x-blue.svg)](https://www.opencart.com/)
[![PHP](https://img.shields.io/badge/PHP-7.2--8.1-777bb4.svg)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Honeypot Anti-Spam CAPTCHA 1.3.1** — многоуровневая защита регистрации и стандартных и AJAX-форм OpenCart 3.x / LiveStore, включая Simple и Uni Login Register. Модуль объединяет динамические honeypot-поля, JavaScript-проверку, одноразовые токены, контроль времени заполнения, rate limit, серверную проверку телефона и Yandex SmartCaptcha.

## Yandex SmartCaptcha

В версии 1.3.1 Yandex SmartCaptcha встроена в Honeypot как отдельный блок настроек.

Доступны два режима:

- **Стандартный модуль Yandex** — используются `captcha_yandex_key` и `captcha_yandex_secret`, уже сохранённые в OpenCart/LiveStore.
- **Собственные ключи Honeypot** — Site key и Secret key задаются непосредственно в настройках Honeypot. Это позволяет использовать SmartCaptcha даже если отдельный модуль Yandex в магазине не установлен или не настроен.

Для регистрации можно отдельно включить вывод SmartCaptcha. Полученный `smart-token` обязательно проверяется на сервере через API Yandex `smartcaptcha.yandexcloud.net/validate`.

Если Yandex уже выбрана основной CAPTCHA OpenCart для страницы регистрации, Honeypot не выводит второй виджет и не дублирует проверку.

### Сложное задание с картинками

Режим повышенной сложности и обязательное визуальное задание настраиваются в **Yandex Cloud** для того Site key, который используется модулем. Сам OpenCart-виджет не должен подменять серверную конфигурацию сложности CAPTCHA. Для максимальной защиты рекомендуется включить в Yandex Cloud усиленную/сложную проверку для используемой CAPTCHA.

## Серверная проверка телефона

В 1.3.1 добавлена независимая серверная проверка поля `telephone` на регистрации. Она работает даже если бот обходит JavaScript-маску браузера.

По умолчанию:

- разрешены только цифры и символы `+ ( ) -` и пробел;
- после удаления форматирования должно остаться 10–11 цифр;
- строки вроде `matveev`, `test`, `123` отклоняются;
- в российском режиме 11-значный номер должен начинаться с `7` или `8`, 10-значный — с `9`.

Нарушение записывается в журнал как `invalid_phone`.

## Основные возможности

- два динамических honeypot-поля;
- случайные имена ловушек;
- одноразовый session-token;
- срок жизни токена;
- привязка токена к User-Agent;
- JavaScript proof;
- минимальное время заполнения;
- rate limit по IP/группе маршрутов с временной блокировкой только за антиспам-отказы;
- совместимость с `account/simpleregister` (Simple) и Uni Login Register (UniShop2);
- автономная Yandex SmartCaptcha;
- использование ключей стандартного Yandex-модуля или собственных ключей;
- серверная проверка телефона;
- журнал причин блокировки;
- опциональное журналирование успешного прохождения регистрации (`registration_passed`);
- фильтры и статистика;
- OCMOD, без VQMod и OpenCart Events.

Пароли и содержимое сообщений модуль не сохраняет.

## Причины в журнале

`honeypot`, `too_fast`, `invalid_token`, `missing_session`, `expired_token`, `client_mismatch`, `missing_trap`, `js_check`, `rate_limit`, `invalid_phone`, `yandex_failed`, `registration_passed`.

## Установка

1. Скачайте `dist/honeypot_antispam_captcha_v1.3.1.ocmod.zip`.
2. Откройте `Дополнения → Установка дополнений` и загрузите ZIP.
3. Перейдите в `Дополнения → Дополнения → CAPTCHA`.
4. Установите и откройте **Honeypot Anti-Spam**.
5. Включите модуль и сохраните настройки.
6. Откройте `Дополнения → Модификаторы` и обновите кеш модификаций.
7. В разделе Yandex SmartCaptcha выберите источник ключей.
8. Если используются собственные ключи — укажите Site key и Secret key.
9. Для максимальной защиты настройте повышенную сложность CAPTCHA в Yandex Cloud.
10. Выполните тестовую регистрацию и проверьте журнал.

## Рекомендуемые параметры

- минимальное время заполнения: 5 секунд;
- JavaScript-проверка: включена;
- срок жизни токена: 1800 секунд;
- rate limit: включён;
- лимит: 6 попыток за 900 секунд;
- блокировка: 1800 секунд;
- серверная проверка телефона: включена;
- журнал успешных регистраций: по необходимости.

## Совместимость

- OpenCart 3.x;
- LiveStore 3.x;
- PHP 7.2–8.1;
- OCMOD: да;
- VQMod: нет;
- Events: нет.

Сторонние темы и модифицированные контроллеры могут менять точки интеграции. После установки необходимо проверить регистрацию на конкретной сборке магазина.

## Скачать

Актуальный пакет находится в каталоге [`dist`](https://github.com/damatveev/Honeypot/tree/main/dist).

## Автор

**Dmitry Matveev**  
E-mail: d.a.matveev@gmail.com

Поддержать разработку: https://boosty.to/matveevd/donate

## Лицензия

MIT.
