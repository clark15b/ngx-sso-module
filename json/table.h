/*
 * Copyright (C) 2020 Anton Burdinuk
 * clark15b@gmail.com
 */

#ifndef __HASH_TABLE_H
#define __HASH_TABLE_H

#include <sys/types.h>

#include <ngx_core.h>

typedef ngx_pool_t json_pool_t;
#define json_palloc(pool,n) ( ngx_palloc(pool,n) )
#define json_memcpy(dst,src,n) ( ngx_memcpy(dst,src,n) )

// размер хэш-таблицы 256
#define JSON_HASH_256          1        // любые символы
#define JSON_HASH_256_95       2        // латинские буквы, цифры и служебные символы, 95 символов
#define JSON_HASH_256_64       3        // латинские буквы, цифры, '-' и '_', 64 символа
#define JSON_HASH_256_38       4        // латинские буквы без учета регистра, цифры, '-' и '_', 38 символов

// размер хэш-таблицы 95
#define JSON_HASH_95           5        // латинские буквы, цифры и служебные символы, 95 символов

// размер хэш-таблицы 64
#define JSON_HASH_64           6        // латинские буквы, цифры, '-' и '_', 64 символа

// размер хэш-таблицы 38
#define JSON_HASH_38           7        // латинские буквы без учета регистра, цифры, '-' и '_', 38 символов

typedef struct
{
    u_int8_t* data;

    size_t len;

} json_str_t;

// элемент таблицы
typedef struct
{
    u_int32_t idx;                      // числовой индекс

    json_str_t key;                     // строковый ключ

    json_str_t value;                   // значение

    void* user_data;                    // указатель на пользовательские данные

    void* next;                         // указатель на следующий элемент

} json_table_elt_t;

// связный список
typedef struct
{
    json_table_elt_t* first;            // указатель на первый элемент

    json_table_elt_t* last;             // указатель на последний элемент

} json_table_list_t;

// таблица
typedef struct
{
    json_pool_t* pool;                  // пул для выделения памяти

    const u_int8_t* symbols;            // алфавит

    const u_int8_t* table;              // таблица перестановок

    json_table_list_t* elts;            // элементы хэш-таблицы

    u_int32_t nelts;                    // количество элементов в таблице

    u_int32_t size;                     // размер вектора (для цисловых индексов)

    void* user_data;                    // указатель на пользовательские данные

    int zero_copy;                      // если 1, то сохраняет указатели на строки вместо выделения памяти и копирования
                                        // важно что бы все строки существовали до окончания использования таблицы
                                        // так же в этом режиме отсутствует null-терминатор
} json_table_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// таблица
json_table_t* json_table_init(json_pool_t* pool,json_table_t* t,int basis);

json_table_t* json_table_new(json_pool_t* pool,int basis);

json_table_elt_t* json_table_find(json_table_t* t,const u_int8_t* key,size_t klen,int no_create);

json_table_elt_t* json_table_set(json_table_t* t,const u_int8_t* key,size_t klen,const u_int8_t* data,size_t len);

// массив
json_table_t* json_array_init(json_pool_t* pool,json_table_t* t,u_int32_t table_size);

json_table_t* json_array_new(json_pool_t* pool,u_int32_t table_size);

json_table_elt_t* json_array_find(json_table_t* t,u_int32_t idx,int no_create);

json_table_elt_t* json_array_set(json_table_t* t,u_int32_t idx,const u_int8_t* data,size_t len);

json_table_elt_t* json_array_push(json_table_t* t);

// общее
json_table_elt_t* json_elt_set(json_table_t* t,json_table_elt_t* elt,const u_int8_t* data,size_t len);

int json_is_table(json_table_t* t);

int json_is_array(json_table_t* t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __HASH_TABLE_H */
