# Инструкция по распространению

Исходный код и готовый `.ocmod.zip` можно распространять в соответствии с MIT License.

## Рекомендуемая карточка

**Название:** Honeypot Anti-Spam CAPTCHA 1.3.4

**Краткое описание:** Усиленная антиспам-защита для OpenCart/LiveStore с honeypot, JavaScript-проверкой, одноразовым токеном, rate limit и дополнительной Yandex SmartCaptcha на регистрации. Использует API-ключи из стандартного модуля Yandex CAPTCHA.

- Тип расширения: CAPTCHA
- OCMOD: Да
- VQMod: Нет
- Events: Нет
- PHP: 7.2–8.1
- OpenCart: 3.x
- LiveStore: 3.x
- Yandex SmartCaptcha: Да, через стандартные или собственные ключи Honeypot

## Файл для публикации

`dist/honeypot_antispam_captcha_v1.3.4.ocmod.zip`

## Перед публикацией

Проверить установку, обновление кеша модификаторов, регистрацию, совместную работу с основной CAPTCHA, отображение Yandex SmartCaptcha и запись блокировок в журнал.

Для автоматической Yandex SmartCaptcha стандартный модуль Yandex CAPTCHA должен быть включён и в нём должны быть заполнены site key и secret.

Сохранять файл LICENSE и сведения об авторе.

Автор: Dmitry Matveev  
Поддержка: https://boosty.to/matveevd/donate
