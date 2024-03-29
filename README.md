# ngx-sso-module
**Nginx JWT access module - Модуль контроля доступа для nginx**

Модуль предназначен для ограничения доступа к ресурсам сайта на уровне web-сервера nginx путем проверки JWT-токена безопасности в каждом запросе.

Допускается передача токена в куке или GET параметре, если в запросе присутствует и то и другое, приоритет у значения GET параметра.
Рекомендуется использование куки т. к. браузер пользователя передает ее автоматически и не нужно протягивать токен в каждый запрос.

Модуль поддерживает единственный алгоритм подписи: HS256 (HMAC + SHA256).

Для проверки подписи модулю в настройках необходимо передать ключ, используемый IdP (Identity provider) при формировании токена (общий секрет). Никто кроме этих двух сторон не должен знать ключ!

По умолчанию модуль всегда пропускает запросы к корню сайта ("/") и страницам авторизации и запроса дополнительных прав доступа, указанных в настройках.
Если этого недостаточно, можно отключить проверку для определенных локаций (например, к "/index.html", см. пример ниже) или типов файлов (например, "js", "css", "jpeg").
Такой подход позволяет активировать защиту по умолчанию начиная с самого корня и выборочно допустить анонимных пользователей к статике или публичным ресурсам сайта.

Каждый запрос к любому ресурсу, не попадающему в исключения, проходит несколько проверок:
1. Наличие токена в куке или GET параметре
2. Проверка JWT подписи IdP
3. Корректность формата тела токена
4. Срок действия токена, если указан клейм "exp"
5. IP адрес клиента, если указан клейм "ipv4"
6. Проверка полномочий для доступа именно к этому разделу согласно списку в клейме "allow"

В случае сбоя проверки на этапах 1-5 модуль переадресует пользователя на страницу логина, указанную в настройках. При переадресации можно применять шаблонные параметры ${name}, где name — название параметра. Если переадресация происходит из-за сбоя на этапах 4-6, при редиректе можно указать любой клейм из токена в качестве названия шаблонного параметра. В противном случае единственный доступный шаблонный параметр — uri (запрошенный ресурс).

Если текущая локация отсутствует в списке разрешенных (клейм "allow") модуль переадресует пользователя на страницу запроса дополнителььных прав, указанную в настройках.

В списке разрешений перечисляются все URI до второго слеша к содержимому которых должен быть предоставлен рекурсивный доступ, например:

    "allow": ["private", "cabinet", "arch" ]

говорит о следующем: разрешен рекурсивный доступ к перечисленным директориям и всем вложенным ресурсам.
Например, в данном случае доступ будет предоставлен к:
* http://hostname/private
* http://hostname/private/
* https://hostname/private
* http://hostname:8080/private
* http://hostname/arch?id=5
* http://hostname/arch/index.html
* http://hostname/arch/static/image.jpeg
* http://hostname/cabinet

и т.д.

Для клейма allow допускается единственное строковое значение "*", в этом случае доступ предоставляется ко всем защищенным разделам сайта. Например:

    "allow": "*"

В теле токена могут содержаться клеймы "exp", "ipv4" и обязательно должен содержаться "allow".

Примеры тела токена:

Предъявивший имеет рекурсивный доступ к /private/* , /cabinet/* и /arch/* без ограничения времени (в случае куки зависит от срока действия куки) с любого хоста в сети:

    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
      "allow": ["private", "cabinet", "arch"]
    }

Предъявивший имеет рекурсивный доступ к /private/* , /cabinet/* и /arch/* до 1591628365 секунды с 00:00:00 01 января 1970 года по UTC с хоста с адресом 127.0.0.1:

    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
      "allow": ["private", "cabinet", "arch"],
      "exp": 1591628365,
      "ipv4": "127.0.0.1"
    }

Предъявивший имеет доступ ко всему без ограничения времени (в случае куки зависит от срока действия куки) с любого хоста в сети:

    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
      "allow": "*"
    }

Для использования модуля обязательно иметь две ссылки:
* Для логина в закрытую часть портала
* Для запроса дополнительных прав

Страница логина после успешной авторизации пользователя должна сформировать JWT токен и разместить его в куке с названием, совпадающим со значением sso_cookie_name из файла настроек nginx. Обязательно перечислить все разделы сайта, куда у пользователя есть доступ в клейме "allow". Авторизация может происходить, например, с использованием технологии SAML.
Так же рекомендуется что бы страница логина воспринимала GET параметр return_url, и производила редирект туда после успешной авторизации и формирования токена. В случае отсутствия return_url переадресация может происходить, например, в личный кабинет пользователя.

Страница запроса дополнительных прав может принимать uri сервиса, куда пользователь попытался попасть и куда у него нет доступа, с помощью соответствующего GET параметра и идентификатор пользователя из соответствующего клейма токена, так же переданного в одном из GET параметров.
Это поможет сформировать заявку на дополнительные права для службы технической поддержки, проверить статус ранее сформированной заявки или просто уведомить пользователя о том, что доступ в данный раздел у него отсутствует.

Для сборки модуля необходимо получить исходные тексты nginx нужной версии и распаковать их.
Далее переходим в директорию с исходными текстами nginx, например:

    cd nginx-1.10.3

    # Конфигурируем nginx с указанием полного пути к файлу ngx_sso_module.c, например:
    ./configure --add-dynamic-module=/root/ngx-sso-module/

    # Затем выполняем сборку модуля:
    make modules

    # И копируем под root модуль ngx_sso_module.so из nginx-1.10.3/objs в директорию с модулями nginx, например: 
    sudo cp ./objs/ngx_sso_module.so /usr/local/nginx/modules/

Важно! Nginx должен быть собран с поддержкой OpenSSL т.к. модуль использует данную библиотеку для проверки JWT подписи.

Для загрузки модуля, в корневую секцию файла nginx.conf необходимо добавить:
load_module modules/ngx_sso_module.so;

Следующие директивы могут располагаться в корневой секции, в http, в server, location и наследуются на более низкие уровни:

**sso**

Включает или выключает проверки для локации, допускает значения «on» или «off» и должен использоваться для управлением исключениями на уровне локаций. Если явно не включить для локации или на уровнях выше — проверка отключена. Рекомендуется включать для "/" и выключать выборочно для локаций более низкого уровня.

**sso_any**
Включает режим, при котором не происходит проверки прав, достаточно валидного токена, поле allow может полностью отсутствовать. Допустимые значения «on» или «off».

**sso_psk**

Общий с IdP (страницей логина) ключ, нужен для проверки подписи, допускает одно строковое значение.

**sso_cookie_name**

Название куки, в которой искать токен, если не указать — в куках токен искаться не будет.

**sso_url_name**

Название GET параметра, в котором искать токен, если не указать — в GET параметрах токен искаться не будет.

**sso_exclude**

Содержит список расширений файлов через пробел или путей, начинающихся с "/", на которые не распространяются проверки (для путей все что начинается с указанного значения и глубже).

**sso_login_page**

Определяет URI страницы логина на портале, куда производить редирект в случае полного отсутствия или недействительности токена, допускается использование шаблонных параметров ${uri} (текущий URI для возврата) и любых клеймов первого уровня из токена, если удалось его разобрать (клеймы доступны только если отказ произошел из-за проверки срока действия или IP).

**sso_request_page**

Определяет URI страницы запроса дополнительных прав на портале, куда производить редирект в случае отсутствия разрешения на доступ к текущему разделу в клейме "allow", допускается использование шаблонных параметров ${uri} (текущий URI для определения раздела, к которому нужен доступ) и любых клеймов первого уровня из токена, которые позволят идентифицировать пользователя, например ${name}.

Пример nginx.conf:
    
    load_module modules/ngx_sso_module.so;

    ...

    server {

        ...

        sso_psk secret;
        sso_cookie_name token;
        sso_url_name token;
        sso_login_page /login.html?return_url=${uri};
        sso_request_page /request.html?user=${name}&location=${uri};
        sso_exclude jpeg css js /path/;

        ...

        location / {
            sso on;

            ...
        }
 
        location /index.html {
            sso off;
        }

        location /news/ {
            sso off;
        }


Пример тестового запроса:

    wget -O - "http://hostname/private/?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhbGxvdyI6IioifQ.GhPA9vWxI2FGnpEKWDoK9Ai1qjH9M080kuxZvgrhtNs" 2>/dev/null

Тестовые токены можно формировать с использованием https://jwt.io , выбрав алгоритм HS256 и указав значение sso_psk в качестве секрета для формирования HMACSHA256 подписи.
