# Honeypot Anti-Spam CAPTCHA for OpenCart 3 / LiveStore

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/damatveev/Honeypot/releases)
[![OpenCart](https://img.shields.io/badge/OpenCart-3.x-blue.svg)](https://www.opencart.com/)
[![PHP](https://img.shields.io/badge/PHP-7.2--8.1-777bb4.svg)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Honeypot Anti-Spam CAPTCHA** — невидимая дополнительная защита форм OpenCart 3.x / LiveStore от автоматического спама и ботов. Расширение устанавливается как тип **CAPTCHA** и может работать параллельно с Google CAPTCHA, Yandex CAPTCHA или Basic CAPTCHA.

English: Honeypot Anti-Spam CAPTCHA is an OpenCart 3.x / LiveStore extension that adds an invisible anti-bot layer to standard forms. It can work alongside Google, Yandex or Basic CAPTCHA and includes bot logging and statistics.

## Версия 1.1.0

Honeypot работает **вместе** с Google CAPTCHA, Yandex CAPTCHA или Basic CAPTCHA и не требует отключения выбранной основной CAPTCHA.

Для двухуровневой защиты оставьте текущую CAPTCHA выбранной в настройках магазина и включите Honeypot Anti-Spam отдельно. OCMOD добавляет скрытую проверку параллельно основной CAPTCHA.

## Возможности

- невидимое honeypot-поле без `display:none`;
- случайное имя поля-ловушки;
- одноразовый токен формы;
- проверка минимального времени заполнения;
- совместная работа с Google / Yandex / Basic CAPTCHA;
- журнал e-mail, имени, IP, User-Agent, route, причины и времени обнаружения;
- фильтры и статистика в административной панели;
- настраиваемый срок хранения журнала;
- QR-код и ссылка для поддержки разработки;
- OCMOD + стандартный механизм CAPTCHA OpenCart;
- VQMod и OpenCart Events не требуются.

Пароли и содержимое сообщений модуль не сохраняет.

## Как работает защита

Обычный посетитель не видит дополнительной CAPTCHA. Автоматизированная отправка может быть обнаружена по заполнению скрытого поля, некорректному токену или подозрительно быстрому заполнению формы. Обнаруженные попытки могут записываться в журнал для последующего анализа.

Honeypot является дополнительным антиспам-слоем и не должен рассматриваться как замена всем механизмам защиты сайта.

## Установка

1. Скачайте `dist/honeypot_antispam_captcha_v1.1.0.ocmod.zip`.
2. Откройте `Дополнения → Установка дополнений` и загрузите ZIP.
3. Перейдите в `Дополнения → Дополнения` → тип `CAPTCHA`.
4. Установите и откройте **Honeypot Anti-Spam**.
5. Включите расширение.
6. Откройте `Дополнения → Модификаторы` и обновите кеш модификаций.
7. Для двухуровневой защиты **оставьте Google/Yandex/Basic выбранной основной CAPTCHA**.
8. Проверьте защищаемые формы после установки.

## Стандартные страницы

Интеграция рассчитана на стандартные формы OpenCart/LiveStore: регистрацию, регистрацию при оформлении заказа, гостевое оформление, контакты, отзывы товара и возвраты — при наличии соответствующих стандартных контроллеров.

## Совместимость

- OpenCart 3.x;
- LiveStore 3.x;
- PHP 7.2–8.1;
- рекомендуемый диапазон PHP 7.4–8.1;
- OCMOD: да;
- VQMod: нет;
- Events: нет.

Сторонние темы, OCMOD и изменённые контроллеры могут влиять на точки интеграции. После установки рекомендуется проверить применение модификаций и работу форм на конкретной сборке магазина.

## Скачать

Актуальные версии публикуются в [GitHub Releases](https://github.com/damatveev/Honeypot/releases). Готовый пакет текущей версии также находится в каталоге [`dist`](https://github.com/damatveev/Honeypot/tree/main/dist).

## Keywords

OpenCart, OpenCart 3, LiveStore, ocStore, honeypot, anti-spam, antispam, spam protection, CAPTCHA, bot protection, form security, invisible captcha, OCMOD, PHP, ecommerce, OpenCart extension, OpenCart module, защита от спама, защита от ботов.

## Поддержка проекта / Donate

Если модуль оказался полезен, разработку можно поддержать:

https://boosty.to/matveevd/donate

QR-код для поддержки проекта включён в административный интерфейс модуля.

## Автор

**Dmitry Matveev**  
E-mail: d.a.matveev@gmail.com

## Лицензия

Распространяется по лицензии [MIT](LICENSE).