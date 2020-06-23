/*
 * Copyright (C) 2020 Anton Burdinuk
 * clark15b@gmail.com
 */

#ifndef __JSON_H
#define __JSON_H

#include "table.h"

#define JSON_TABLE      1
#define JSON_ARRAY      2

// обработчик
typedef struct
{
    int (*open) (void* ctx,int depth,int type);

    int (*name) (void* ctx,int depth,const u_int8_t* p,int len);

    int (*data) (void* ctx,int depth,const u_int8_t* p,int len);

    int (*close)(void* ctx,int depth,int type);

} json_handler_t;

typedef struct
{
    json_pool_t* pool;

    int basis;

    int array_size;

    int zero_copy;

    json_table_t* top;          // корень дерева

    json_table_t* cur;          // текущая таблица

    json_table_elt_t* elt;      // текущий элемент

} json_eval_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// разбор JSON выражения
int json_parse(const u_int8_t* p,int len,json_handler_t* h,void* ctx);

json_table_t* json_eval(json_pool_t* pool,const u_int8_t* p,int len,int basis,int array_size,int zero_copy);

// шаблонизатор
size_t json_url_eval(const u_int8_t* src,size_t slen,u_int8_t* dst,size_t dlen,json_table_t* t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __JSON_H */
