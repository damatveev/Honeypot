Honeypot Anti-Spam CAPTCHA for OpenCart / LiveStore

Версия 1.4.0

Усиленная антиспам-защита регистрации для OpenCart 3.x / LiveStore.

Основные возможности:
- два скрытых honeypot-поля;
- одноразовый session-token;
- срок жизни токена;
- проверка User-Agent;
- JavaScript-проверка;
- контроль минимального времени заполнения;
- rate limit по IP/route;
- журнал блокировок;
- совместная работа с Google / Yandex / Basic CAPTCHA;
- дополнительная Yandex SmartCaptcha на регистрации;
- защита стандартной регистрации, Simple и Uni Login Register;
- rate limit только по антиспам-отказам.

Yandex SmartCaptcha

Если стандартный модуль Yandex CAPTCHA включён и в нём уже настроены site key и secret, Honeypot использует эти существующие настройки автоматически. Повторно вводить API-ключи в Honeypot не требуется.

Если Yandex уже выбрана основной CAPTCHA для регистрации, второй визуальный виджет не добавляется. Honeypot продолжает работать как дополнительный скрытый слой защиты.

Установка

1. Скачайте dist/honeypot_antispam_captcha_v1.4.0.ocmod.zip.
2. Дополнения → Установка дополнений → загрузите ZIP.
3. Дополнения → Дополнения → тип CAPTCHA.
4. Установите и откройте Honeypot Anti-Spam.
5. Включите расширение.
6. Дополнения → Модификаторы → обновите кеш модификаций.
7. Для Yandex SmartCaptcha убедитесь, что стандартный модуль Yandex CAPTCHA включён и настроен.
8. Проверьте регистрацию и журнал блокировок.

Рекомендуемые параметры:
- минимальное время заполнения: 5 секунд;
- JavaScript-проверка: Да;
- срок жизни токена: 1800 секунд;
- rate limit: Да;
- лимит: 6 попыток;
- окно: 900 секунд;
- блокировка: 1800 секунд.

Причины блокировки:
honeypot, too_fast, invalid_token, missing_session, expired_token, client_mismatch, missing_trap, js_check, rate_limit, yandex_failed.

Совместимость

OpenCart 3.x / LiveStore 3.
PHP 7.2–8.1, рекомендуемый диапазон 7.4–8.1.
OCMOD: Да.
VQMod: Нет.
Events: Нет.

Автор

Dmitry Matveev
d.a.matveev@gmail.com

Поддержать разработку: https://boosty.to/matveevd/donate

Лицензия

MIT.
