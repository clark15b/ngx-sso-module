/*
 * Copyright (C) 2020 Anton Burdinuk
 * clark15b@gmail.com
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "json.h"

#define NGX_SSO_LOCATION_LEN    512

// конфигурация модуля
typedef struct
{
    ngx_flag_t enable;          // 1 - включен для текущей локации

    ngx_str_t cookie_name;      // название cookie для поиска токена доступа

    ngx_str_t url_name;         // название GET параметра для поиска токена доступа

    ngx_str_t psk;              // общий с IdP секрет (ключ)

    ngx_str_t login_page;       // страница логина с опциональным return_url в качестве параметра

    ngx_str_t request_page;     // страница запроса прав в данный раздел с информацией о пользователе и локейшене сервиса в параметрах

    ngx_array_t* exclude;       // исключения

    ngx_flag_t any;             // 1 - пропускает с любым валидным токеном не проверяя права

}ngx_sso_loc_conf_t;

static ngx_int_t ngx_sso_handler(ngx_http_request_t* r);

// инициализация модуля
static ngx_int_t ngx_sso_init(ngx_conf_t* cf)
{
    ngx_http_handler_pt* h; ngx_http_core_main_conf_t* cmcf;

    cmcf=ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);

    if(cmcf)
    {
        h=ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

        if(h)
            *h=ngx_sso_handler;
    }

    return NGX_OK;
}

// разбор sso_exclude
static char* ngx_sso_conf_set_str_array_slot(ngx_conf_t* cf,ngx_command_t* cmd,void* conf)
{
    ngx_sso_loc_conf_t* lcf=conf;

    ngx_str_t* value=cf->args->elts;

    ngx_uint_t i;

    if(!lcf->exclude)
    {
        lcf->exclude=ngx_array_create(cf->pool,1,sizeof(ngx_str_t));

        if(!lcf->exclude)
            return NGX_CONF_ERROR;
    }

    for(i=1;i<cf->args->nelts;++i)
    {
        if(value[i].len!=4 || ngx_strncmp(value[i].data,"none",4))
        {
            ngx_str_t* s=ngx_array_push(lcf->exclude);

            if(!s)
                return NGX_CONF_ERROR;

            s->data=value[i].data;

            s->len=value[i].len;
        }
    }

    return NGX_CONF_OK;
}

// инициализация узла конфигурации
static void* ngx_sso_create_loc_conf(ngx_conf_t* cf)
{
    ngx_sso_loc_conf_t* conf=ngx_pcalloc(cf->pool,sizeof(ngx_sso_loc_conf_t));

    conf->enable=NGX_CONF_UNSET;

    conf->exclude=NULL;

    conf->any=NGX_CONF_UNSET;

    return conf;
}

// слияние узла конфигурации
static char* ngx_sso_merge_loc_conf(ngx_conf_t* cf,void* parent,void* child)
{
    // почему-то не наследуются родительские значения если в конфиге явно объявить дочернюю локацию
    ngx_sso_loc_conf_t* prev=parent;

    ngx_sso_loc_conf_t* conf=child;

    ngx_conf_merge_value(conf->enable,prev->enable,0);

    ngx_conf_merge_str_value(conf->cookie_name,prev->cookie_name,"");

    ngx_conf_merge_str_value(conf->url_name,prev->url_name,"");

    ngx_conf_merge_str_value(conf->psk,prev->psk,"");

    ngx_conf_merge_str_value(conf->login_page,prev->login_page,"");

    ngx_conf_merge_str_value(conf->request_page,prev->request_page,"");

    if(!conf->exclude)
        conf->exclude=prev->exclude;

    ngx_conf_merge_value(conf->any,prev->any,0);

    return NGX_CONF_OK;
}

// параметры модуля
static ngx_command_t ngx_sso_commands[]=
{
    {
        // вкл/выкл
        ngx_string("sso"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,enable),
        NULL
    },
    {
        // название куки с токеном
        ngx_string("sso_cookie_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,cookie_name),
        NULL
    },
        // название GET параметра с токеном
    {
        ngx_string("sso_url_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,url_name),
        NULL
    },
    {
        // общий ключ
        ngx_string("sso_psk"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,psk),
        NULL
    },
    {
        // ссылка для авторизации
        ngx_string("sso_login_page"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,login_page),
        NULL
    },
    {
        // ссылка для запроса расширенных прав
        ngx_string("sso_request_page"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,request_page),
        NULL
    },
    {
        // список типов файлов для исключения из алгоритма проверки прав
        ngx_string("sso_exclude"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_sso_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        // режим когда достаточно любого валидного токена
        ngx_string("sso_any"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_sso_loc_conf_t,any),
        NULL
    },
    ngx_null_command
};

// контекст модуля
static ngx_http_module_t ngx_sso_module_ctx=
{
    NULL,                       // preconfiguration
    ngx_sso_init,               // postconfiguration

    NULL,                       // create main configuration
    NULL,                       // init main configuration

    NULL,                       // create server configuration
    NULL,                       // merge server configuration

    ngx_sso_create_loc_conf,    // create location configuration
    ngx_sso_merge_loc_conf,     // merge location configuration
};

// описание модуля
ngx_module_t ngx_sso_module=
{
    NGX_MODULE_V1,
    &ngx_sso_module_ctx,        // контекст модуля
    ngx_sso_commands,           // команды
    NGX_HTTP_MODULE,            // тип модуля
    NULL,                       // init master
    NULL,                       // init module
    NULL,                       // init process
    NULL,                       // init thread
    NULL,                       // exit thread
    NULL,                       // exit process
    NULL,                       // exit master
    NGX_MODULE_V1_PADDING
};

// сревнение URI, где от последнего аргумента предварительно отрезаются GET параметры
static ngx_int_t ngx_sso_compare_uri(ngx_str_t* s1,ngx_str_t* s2)
{
    ngx_str_t s; u_char *p,*end;

    s.data=s2->data; s.len=s2->len;

    if(s.len>0)
    {
        end=s.data+s.len;

        p=ngx_strlchr(s.data,end,'?');  // для оптимизации лучше вынести на этап конфигурации модуля

        if(p)
            s.len=p-s.data;
    }

    if(s1->len!=s.len || ngx_strncmp(s1->data,s.data,s.len))
        return NGX_ERROR;

    return NGX_OK;
}

// разделение строки на две части по границе последней точки
static ngx_int_t ngx_sso_split_last_dot(ngx_str_t* src,ngx_str_t* s1,ngx_str_t* s2)
{
    size_t n;

    for(n=src->len;n>0 && src->data[n-1]!='.';--n);

    s1->data=src->data;

    if(n>0)     // нашли разделитель
    {
        s2->data=src->data+n; s2->len=src->len-n;
        s1->len=n-1;
    }else
    {
        s1->len=src->len;
        s2->len=0;
    }

    return NGX_OK;
}

// поиск расширения файла в списке исключений
static ngx_int_t ngx_sso_find_exclude(ngx_http_request_t* r,ngx_array_t* lst)
{
    ngx_str_t name,ext=ngx_null_string,*s=lst->elts;

    ngx_uint_t i; int has_ext=0;

    if(ngx_sso_split_last_dot(&r->uri,&name,&ext)==NGX_OK)
        has_ext=1;

    for(i=0;i<lst->nelts;++i)   // для оптимизации желательно применить хэш-таблицу, заполняемую при разборе конфига
    {
        if(s[i].len>0 && s[i].data[0]=='/')
        {
            if(!ngx_strncmp(r->uri.data,s[i].data,s[i].len))
                return NGX_OK;
        }else
        {
            if(has_ext==1 && ext.len==s[i].len && !ngx_strncmp(ext.data,s[i].data,ext.len))
                return NGX_OK;
        }
    }

    return NGX_ERROR;
}

// base64url декодирование
static ngx_int_t ngx_sso_base64decode(ngx_http_request_t* r,ngx_str_t* src,ngx_str_t* dst)
{
    dst->len=ngx_base64_decoded_length(src->len);

    if(dst->len<1)
        return NGX_ERROR;

    dst->data=ngx_pcalloc(r->pool,dst->len);    // память выделяется внутри в пуле, освобождения не требует

    if(!dst->data)
        return NGX_ERROR;

    return ngx_decode_base64url(dst,src);
}

// проверка подписи токена, срока действия, IP клиента и извлечение тела
static ngx_int_t ngx_sso_validate_token(ngx_http_request_t* r,ngx_sso_loc_conf_t* cf,ngx_str_t* token,json_table_t** pt)
{
    ngx_str_t jwt_data,jwt_dgst,jwt_dgst_decoded,jwt_hdr,jwt_body,body;

    json_table_t* t; time_t now=ngx_time(); json_table_elt_t* elt;

    unsigned char md[EVP_MAX_MD_SIZE];

    unsigned int md_len=sizeof(md);

    if(token->len<1)                                                    // токен отсутствует
        return NGX_ERROR;

    if(ngx_sso_split_last_dot(token,&jwt_data,&jwt_dgst)!=NGX_OK)       // разделяем данные и подпись
        return NGX_ERROR;

    if(jwt_dgst.len!=43)        // судя по длине это точно не HS256, проверять не пытаемся
        return NGX_ERROR;

    if(ngx_sso_base64decode(r,&jwt_dgst,&jwt_dgst_decoded)!=NGX_OK)     // декодируем подпись в бинарный вид
        return NGX_ERROR;

    if(!HMAC(EVP_sha256(),cf->psk.data,cf->psk.len,jwt_data.data,jwt_data.len,md,&md_len))      // вычисляем подпись
        return NGX_ERROR;

    if(md_len!=jwt_dgst_decoded.len || ngx_memcmp(md,jwt_dgst_decoded.data,md_len))     // сравниваем подписи
        return NGX_ERROR;

    // подпись корректная, извлекаем тело

    if(ngx_sso_split_last_dot(&jwt_data,&jwt_hdr,&jwt_body)!=NGX_OK)    // разделяем заголовок и данные
        return NGX_ERROR;

    if(ngx_sso_base64decode(r,&jwt_body,&body)!=NGX_OK)  // декодируем тело токена
        return NGX_ERROR;

    t=json_eval(r->pool,body.data,body.len,JSON_HASH_95,25,1);    // парсим JSON

    if(!t)
        return NGX_ERROR;

    *pt=t;

    elt=json_table_find(t,(u_int8_t*)"exp",3,1);

    if(elt && ngx_atoi(elt->value.data,elt->value.len)<now)     // проверка срока действия, если указан
        return NGX_ERROR;

    elt=json_table_find(t,(u_int8_t*)"ipv4",4,1);

    if(elt && r->connection->sockaddr->sa_family==AF_INET &&
        ngx_inet_addr(elt->value.data,elt->value.len)!=((struct sockaddr_in*)r->connection->sockaddr)->sin_addr.s_addr)
            return NGX_ERROR;   // проверка IP адреса клиента, если указан

    return NGX_OK;
}

// проверка прав доступа к ресурсу
static ngx_int_t ngx_sso_validate_permissions(ngx_http_request_t* r,json_table_t* t)
{
    u_int32_t i;

    u_char* p;

    u_char* uri=r->uri.data+1;

    size_t len=r->uri.len-1;

    json_table_elt_t* perm=json_table_find(t,(u_int8_t*)"allow",5,1);

    if(!perm)                                   // клейм является обязательным, без него никуда не попасть.
        return NGX_ERROR;                       // если тут заменить на NGX_OK, то атрибут становится опциональным
                                                // и без него можно ходить куда угодно, главное иметь действительный токен

    // пропускаем если allow содержит строковое значение '*'
    if(perm->value.len==1 && perm->value.data[0]=='*')
        return NGX_OK;

    // в противном случае allow должен содержать список локаций
    if(!perm->user_data)
        return NGX_ERROR;

    p=ngx_strlchr(uri,uri+len,'/');

    if(p)
        len=p-uri;

    for(i=0;i<((json_table_t*)perm->user_data)->size;++i)
    {
        json_table_elt_t* elt=json_array_find(perm->user_data,i,1);

        if(elt && elt->value.len==len && !ngx_strncmp(elt->value.data,uri,len))
            return NGX_OK;
    }

    return NGX_ERROR;
}

// обработчик
static ngx_int_t ngx_sso_handler(ngx_http_request_t* r)
{
    ngx_sso_loc_conf_t* cf;

    ngx_int_t retval=NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_str_t token=ngx_null_string;

    ngx_str_t location;

    json_table_t* t=NULL;

    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,"%V, %V",&r->uri,&r->args);

    if(r->uri.len==1 && r->uri.data[0]=='/')    // доступ к корню есть всегда что бы можно было включить защиту с корня,
        return NGX_OK;                          // не нарушая работоспособность портала для пользователей без токена

    cf=ngx_http_get_module_loc_conf(r,ngx_sso_module);

    if(!cf || cf->enable!=1)                    // не пременимо для текущей локации, пропускаем
        return NGX_OK;

    if(cf->exclude && ngx_sso_find_exclude(r,cf->exclude)==NGX_OK)
        return NGX_OK;                          // пропускаем исключения согласно списку типов файлов

    if(ngx_sso_compare_uri(&r->uri,&cf->login_page)==NGX_OK || ngx_sso_compare_uri(&r->uri,&cf->request_page)==NGX_OK)
        return NGX_OK;                          // пропускаем к странице для логина и странице запроса расширенных прав

    if(cf->url_name.len>0)                      // поиск токена в GET параметре (приоритет перед cookie)
    {
        if(ngx_http_arg(r,cf->url_name.data,cf->url_name.len,&token)!= NGX_OK)
            token.len=0;
    }

    if(token.len<1 && cf->cookie_name.len>0)    // поиск токена в cookie
    {
#if (nginx_version>1022001)
        // для версии nginx > 1.22.1
        if(!ngx_http_parse_multi_header_lines(r,r->headers_in.cookie,&cf->cookie_name,&token))
#else
        if(ngx_http_parse_multi_header_lines(&r->headers_in.cookies,&cf->cookie_name,&token)!=NGX_OK)
#endif
            token.len=0;
    }

    // все предпроверки прошли, готовимся принимать решение на основе содержимого токена
    t=json_table_new(r->pool,JSON_HASH_95);     // таблица для шаблонизатора по умолчанию, на случай если не получится разобрать JWT

    location.data=ngx_palloc(r->pool,NGX_SSO_LOCATION_LEN);

    location.len=0;

    if(!t || !location.data)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    t->zero_copy=1;

    if(ngx_sso_validate_token(r,cf,&token,&t)!=NGX_OK)  // проверка на наличие токена и на корректность подписи
        retval=NGX_HTTP_MOVED_TEMPORARILY;

    json_table_set(t,(u_int8_t*)"uri",3,r->uri.data,r->uri.len);

    if(retval==NGX_HTTP_MOVED_TEMPORARILY)              // токен отсутствует или не действителен, редирект на авторизацию
        location.len=json_url_eval(cf->login_page.data,cf->login_page.len,location.data,NGX_SSO_LOCATION_LEN,t);
    else if(!cf->any && ngx_sso_validate_permissions(r,t)!=NGX_OK)  // проверка прав доступа к этому uri, редирект на запрос прав
    {
        location.len=json_url_eval(cf->request_page.data,cf->request_page.len,location.data,NGX_SSO_LOCATION_LEN,t);

        retval=NGX_HTTP_MOVED_TEMPORARILY;
    }else
        retval=NGX_OK;

    if(retval==NGX_HTTP_MOVED_TEMPORARILY)
    {
        r->headers_out.location=ngx_list_push(&r->headers_out.headers);

        if(!r->headers_out.location)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        r->headers_out.location->hash=1;
        ngx_str_set(&r->headers_out.location->key,"Location");
        r->headers_out.location->value.data=location.data;
        r->headers_out.location->value.len=location.len;
    }

    return retval;
}
