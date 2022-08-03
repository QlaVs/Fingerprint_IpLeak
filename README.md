# Fingerprint_IpLeak

Тестовое задание для НеоБИТ:
Разработать веб-сайт проверки анонимности веб-браузера, который позволит распознать пользователя даже после смены браузера или настройки прокси/VPN/TOR.

___
Веб-приложение: https://qlvz.pythonanywhere.com  
Иногда загрузка может быть долгой из-за проверки VPN (Проблема описана ниже в разделе [VPN](#VPN))
___

На странице отображаются:
- IP-адрес
- Посещалась ли страница ранее
- Использование прокси (не всегда определяет)
- Использование VPN
- Использование TOR
- Наличие HTTP-загловков прокси-серверов
- Предупреждение при раличии системного времени и времени на основании IP-адреса
___
#### Пример веб-интерфейса при включенном VPN (при этом страница уже была посещена ранее без VPN):
![Пример](https://github.com/QlaVs/Fingerprint_IpLeak/blob/master/images/Example.jpg "Пример")
___
### IP-адрес
Адрес получается через библиотеку Ipware
___
### Was here before
Определяется по совокупности факторов, используются куки, проверка user_agent и данные в БД. При обнаружении какого-либо из факторов может выдаваться
результат ```Traces found```.
___
### Proxy
Определяется по наличию заголовков прокси, т.е. если нет заголовков в запросе - данное поле также будет False
Наличие заголовков не всегда способно однозначно определить наличие прокси, поэтому могут быть ложные несрабатывания.
___
### VPN
Определяется с помощью данных с сервиса [IpQualityScore](https://www.ipqualityscore.com/).  
```!ВАЖНО!``` Так как приложение размещено на сервисе [PythonAnywhere](www.pythonanywhere.com) и используется бесплатный тарифный план хостинга,
то имеются ограничения: через ```requests.get()``` можно отправлять запросы только на сайты из списка 
[Whitelist](https://www.pythonanywhere.com/whitelist/).  
В списке есть GitHub, поэтому я создал страницу для переадресации API с сервиса IQS на небольшой
[ByPass](https://github.com/QlaVs/QlaVs.github.io/tree/master/ipredir), рамещенный на Github Pages.  
Данное решение также может быть использовано для других API (при необходимости).
___
### TOR
Определяется через готовый список известных [Exit-адресов сервиса TOR](https://check.torproject.org/exit-addresses). В моем случае список хранится в файле из-за
описаного ранее ограничения по requests-запросам на PythonAnywhere.
___
### Proxy Headers
Заголовки хранятся в списке, далее проверяется их наличие в заголовках в теле запроса. При совпадении выводится результат True
___
### Проверка системного времени
Дополнительно проверяется локальное системное время и время, основанное на временной зоне IP-адреса. При несовпадении может выдаваться предупреждение.  
Также, такой параметр может быть косвенным фактором использования средств сокрытия IP-адреса.  
Для нахождения времени по IP определяем временную зону пользователя (использем ранее описанный ByPass, так как IQS содержит много полезной информации)
и далее, через ```pytz.timezone``` получаем время. Сравнение происходит непосредственно через JavaScript.
___
Использованные технологии:
- Python
- Django
- Ipware
- Asyncio
- Pyppeteer
- Request-html
- Pytz
- Chromium
- HTML
- JavaScript
- Bootstrap
