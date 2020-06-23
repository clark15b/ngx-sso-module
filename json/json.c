/*
 * Copyright (C) 2020 Anton Burdinuk
 * clark15b@gmail.com
 */

#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include "json.h"

#define JSON_MAX_DEPTH  25

// разбор
int json_parse(const u_int8_t* p,int len,json_handler_t* h,void* ctx)
{
    u_int8_t st[JSON_MAX_DEPTH]; u_int8_t c[JSON_MAX_DEPTH];

    int offset=0; int n=0; int rc;

    int idx=0,i,ch;

    st[idx]=0;

    for(i=0;i<len;++i)
    {
        ch=p[i];

        if(ch=='\r' || ch=='\n' || ch=='\t')    // преобразуем все символы разметки в пробелы
            ch=' ';

        switch(st[idx])
        {
        // корень
        case 0:
            if(ch=='{')                         // объект
            {
                if(idx>=JSON_MAX_DEPTH-1)       // достигнута максимальная глубина дерева
                    return -2;
                else
                {
                    if((rc=h->open(ctx,idx,JSON_TABLE)))
                        return rc;

                    st[++idx]=10;
                }
            }else if(ch=='[')                   // массив
            {
                if(idx>=JSON_MAX_DEPTH-1)       // достигнута максимальная глубина дерева
                    return -2;
                else
                {
                    if((rc=h->open(ctx,idx,JSON_ARRAY)))
                        return rc;

                    st[++idx]=20;
                }
            }else if(ch!=' ')
                return -1;
            break;

        // объект
        case 10:
            if(ch=='}')
            {
                if(idx<1)                       // лишняя закрывающая скобка
                    return -3;
                else
                {
                    --idx;

                    if((rc=h->close(ctx,idx,JSON_TABLE)))
                        return rc;
                }
            }else if(ch=='\"')                  // название поля
                { offset=i+1; n=0; st[idx]=11; }
            else if(ch!=' ')
                return -1;
            break;

        case 11:
            if(ch=='\\')
                st[idx]=12;
            else if(ch=='\"')
            {
                n=i-offset;

                st[idx]=13;

                if((rc=h->name(ctx,idx,p+offset,n)))
                    return rc;
            }
            break;

        case 12:
            st[idx]=11;
            break;

        case 13:
            if(ch==':')
                { st[idx]=30; c[idx]=1; }
            else if(ch!=' ')
                return -1;
            break;

        // массив
        case 20:
            if(ch==']')
            {
                if(idx<1)                       // лишняя закрывающая скобка
                    return -3;
                else
                {
                    --idx;

                    if((rc=h->close(ctx,idx,JSON_ARRAY)))
                        return rc;
                }
            }else if(ch!=' ')
                { st[idx]=30; c[idx]=2; --i; }
            break;

        // значение
        case 30:
            if(ch=='{')                         // новый объект
            {
                if(idx>=JSON_MAX_DEPTH-1)       // достигнута максимальная глубина дерева
                    return -2;
                else
                {
                    if((rc=h->open(ctx,idx,JSON_TABLE)))
                        return rc;

                    st[++idx]=10;
                }
            }else if(ch=='[')                   // массив
            {
                if(idx>=JSON_MAX_DEPTH-1)       // достигнута максимальная глубина дерева
                    return -2;
                else
                {
                    if((rc=h->open(ctx,idx,JSON_ARRAY)))
                        return rc;

                    st[++idx]=20;
                }
            }else if(ch=='}' || ch==']')
                { st[idx]=(c[idx]==1)?10:20; --i; }
            else if(ch==',')                   // следующее значение
                { st[idx]=40; --i; }
            else if(ch=='\"')                   // строка
                { offset=i+1; n=0; st[idx]=31; }
            else if(ch=='-' || isalnum(ch))     // число или ключевое слово
                { offset=i; n=0; st[idx]=33; }
            else if(ch!=' ')
                return -1;
            break;

        case 31:
            if(ch=='\\')
                st[idx]=32;
            else if(ch=='\"')
            {
                n=i-offset;

                st[idx]=40;

                if((rc=h->data(ctx,idx,p+offset,n)))
                    return rc;
            }
            break;

        case 32:
            st[idx]=31;
            break;

        case 33:
            if(!isalnum(ch) && ch!='.' && ch!='+' && ch!='-')
            {
                n=i-offset;

                st[idx]=40;

                --i;

                if((rc=h->data(ctx,idx,p+offset,n)))
                    return rc;
            }
            break;

        // разделитель элементов объекта или массива
        case 40:
            if(ch==',')
                st[idx]=(c[idx]==1)?10:20;
            else if(ch=='}' || ch==']')
                { st[idx]=(c[idx]==1)?10:20; --i; }
            else if(ch!=' ')
                return -1;
            break;
        }
    }

    if(idx!=0 && st[idx]!=0)
        return -4;                              // не законченная конструкция

    return 0;
}


static int json_eval_name(void* ctx,int depth,const u_int8_t* p,int len)
{
    json_eval_ctx_t* c=ctx;

    if(!c->cur)
        return -5;

    c->elt=json_table_find(c->cur,p,len,0);

    if(!c->elt)
        return -6;

    return 0;
}

static int json_eval_data(void* ctx,int depth,const u_int8_t* p,int len)
{
    json_eval_ctx_t* c=ctx;

    json_table_elt_t* elt=NULL;

    if(!c->cur)
        return -5;

    elt=c->elt?c->elt:json_array_push(c->cur);

    c->elt=NULL;

    if(!elt || !json_elt_set(c->cur,elt,p,len))
        return -6;

    return 0;
}

static int json_eval_open(void* ctx,int depth,int type)
{
    json_eval_ctx_t* c=ctx;

    json_table_t* t=NULL;

    switch(type)
    {
    case JSON_TABLE:
        t=json_table_new(c->pool,c->basis);
        break;

    case JSON_ARRAY:
        t=json_array_new(c->pool,c->array_size);
        break;
    }

    if(!t)
        return -5;

    t->zero_copy=c->zero_copy;

    t->user_data=c->cur;        // ссылка на родителя

    if(!c->top)
        c->top=c->cur=t;
    else
    {
        json_table_elt_t* elt=c->elt?c->elt:json_array_push(c->cur);

        c->elt=NULL;

        if(!elt)
            return -6;

        elt->user_data=t;
        c->cur=t;
    }

    return 0;
}

static int json_eval_close(void* ctx,int depth,int type)
{
    json_eval_ctx_t* c=ctx;

    if(!c->cur)
        return -5;

    c->cur=c->cur->user_data;

    return 0;
}

json_table_t* json_eval(json_pool_t* pool,const u_int8_t* p,int len,int basis,int array_size,int zero_copy)
{
    json_handler_t h=
    {
        .open           = json_eval_open,
        .name           = json_eval_name,
        .data           = json_eval_data,
        .close          = json_eval_close
    };

    json_eval_ctx_t ctx=
    {
        .pool           = pool,
        .basis          = basis,
        .array_size     = array_size,
        .zero_copy      = zero_copy,
        .top            = NULL,
        .cur            = NULL,
        .elt            = NULL
    };

    if(json_parse(p,len,&h,&ctx))
        return NULL;

    return ctx.top;
}

static size_t json_url_encode(const u_int8_t* src,size_t slen,u_int8_t* dst,size_t dlen)
{
    static const char hex[]="0123456789abcdef";

    size_t i,j;

    for(i=0,j=0;i<slen && j<dlen;++i)
    {
        int ch=src[i];

        if(isalnum(ch))
            dst[j++]=ch;
        else if(ch==' ')
            dst[j++]='+';
        else
        {
            dst[j++]='%';

            if(j<dlen)
            {
                dst[j++]=hex[ (ch>>4) & 0x0f ];

                if(j<dlen)
                    dst[j++]=hex[ ch & 0x0f ];
            }
        }
    }

    return j;
}

size_t json_url_eval(const u_int8_t* src,size_t slen,u_int8_t* dst,size_t dlen,json_table_t* t)
{
    size_t i,j;

    int st=0;

    size_t offset=0;

    for(i=0,j=0;i<slen && j<dlen;++i)
    {
        int ch=src[i];

        switch(st)
        {
        case 0:
            if(ch=='$')
                st=1;
            else
                dst[j++]=ch;
            break;
        case 1:
            if(ch=='{')
                { offset=i+1; st=2; }
            else
            {
                dst[j++]='$';

                if(ch!='$')
                {
                    if(j<dlen)
                        dst[j++]=ch;

                    st=0;
                }
            }
            break;
        case 2:
            if(ch=='}')
            {
                json_table_elt_t* elt=json_table_find(t,src+offset,i-offset,1);

                if(elt)
                    j+=json_url_encode(elt->value.data,elt->value.len,dst+j,dlen-j);

                st=0;
            }
            break;
        }
    }

    return j;
}
