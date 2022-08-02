#include "leptjson.h"
#include <errno.h>
#include <math.h>
#include <iostream>
#include <assert.h>
#include <cstring>

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++;} while(0)
#define PUTC(c, ch) do {*(char*)lept_context_push(c, sizeof(char)) = (ch);} while(0)

typedef struct{
    const char* json;
    char *stack;
    size_t size, top;
}lept_context;

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

static void *lept_context_push(lept_context *c, size_t size){
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size){
        if (c->size == 0){
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size){
            c->size += c->size >> 1;
        }
        c->stack = (char *)realloc(c->stack, c->size);//当前内存后面还有内存，在原来内存空间后面进行扩充，而不是重新开辟然后复制
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size){
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context *c){
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}
//null,true,false
static int lept_parse_literal(lept_context *c, lept_value *v, const char *litertal, lept_type type){
    size_t i;
    EXPECT(c, litertal[0]);
    for (i = 0; litertal[i+1]; i++){
        if(c->json[i] != litertal[i+1]){
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

#define STRING_ERROR(ret) do{ c->top = head; return ret;} while(0)

static const char *lept_parse_hex4(const char *p, unsigned *u){
    *u = 0;
    for(int i = 3;i >= 0;i--){
        unsigned ch = *p++;
        if (ISDIGIT(ch)) *u += ((ch - 48) << (i * 4));
        else if (ISHEX(ch)) *u += ((ch - 86) << (i * 4));
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u){
    
}

static int lept_parse_string(lept_context *c, lept_value *v){
    size_t head = c->top, len;
    unsigned u;
    const char *p;
    EXPECT(c, '\"');
    p = c->json;
    for(;;){
        char ch = *p++;
        switch(ch){
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char*)lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            case '\\':
                switch(*p++){
                    case 'b' : PUTC(c, '\b');break;
                    case 'f' : PUTC(c, '\f');break;
                    case 'n' : PUTC(c, '\n');break;
                    case 'r' : PUTC(c, '\r');break;
                    case 't' : PUTC(c, '\t');break;
                    case '/' : PUTC(c, '/');break;
                    case '\\': PUTC(c, '\\');break;
                    case '\"': PUTC(c, '\"');break;
                    case 'u' :
                        if (!(p = lept_parse_hex4(p, &u))){
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        lept_encode_utf8(c,u);
                        break;

                    default : STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            default:
                if((unsigned char)ch < 0x20){
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                PUTC(c, ch);
        }
    }
}


//Parse Json Number:
//number = [ "-" ] int [ frac ] [ exp ]
//int = "0" / digit1-9 *digit
//frac = "." 1*digit
//exp = ("e" / "E") ["-" / "+"] 1*digit
static int lept_parse_number(lept_context *c, lept_value *v){
    const char *p = c->json;
    //遇到-直接跳过
    if(*p == '-') p++;
    //0后面必须是. or nothing
    if(*p == '0') p++;
    else{
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.'){
        p++;
        if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for(p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL)){
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}
//value = null/false/true 
static int lept_parse_value(lept_context *c, lept_value *v){
    switch (*c->json){
        case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
        default : return lept_parse_number(c, v);
        case '"' : return lept_parse_string(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}


//实现 json-text = ws value ws
int lept_parse(lept_value *v, const char *json){
    lept_context c;
    int res;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((res = lept_parse_value(&c, v)) == LEPT_PARSE_OK){
        lept_parse_whitespace(&c);
        if (*c.json != '\0'){ //对*(c.json)取值
            v->type = LEPT_NULL;
            res =  LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return res;
}

lept_type lept_get_type(const lept_value *v){
    assert(v != NULL);
    return v->type;
}
double lept_get_number(const lept_value *v){
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
void lept_set_number(lept_value *v, double n){
    lept_free(v);
    v->n = n;
    v->type = LEPT_NUMBER;
}
void lept_set_string(lept_value *v, const char *s, size_t len){
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s = (char*)malloc(len+1);
    memcpy(v->s, s, len);
    v->s[len] = '\0';
    v->len = len;
    v->type = LEPT_STRING;
}
void lept_free(lept_value *v){
    assert(v != NULL);
    if (v->type == LEPT_STRING){
        free(v->s);
    }
    v->type = LEPT_NULL;
}
size_t lept_get_string_length(const lept_value *v){
    assert(v != NULL && v->type == LEPT_STRING);
    return v->len;
}
const char *lept_get_string(const lept_value *v){
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s;
}
int lept_get_boolean(const lept_value *v){
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}
void lept_set_boolean(lept_value *v, int b){
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}
