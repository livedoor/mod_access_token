
#include "httpd.h"
#include "http_request.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_base64.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define ACCESS_KEY_NAME "AccessKey"
#define EXPIRES_NAME "Expires"
#define SIGNATURE_NAME "Signature"
#define BLOCK_SIZE 64

#define ERR(r, ...) ap_log_rerror(APLOG_MARK, \
                                  APLOG_NOERRNO|APLOG_ERR, 0, r, \
                                  __VA_ARGS__)

#define DBG(r, ...) ap_log_rerror(APLOG_MARK, \
                                  APLOG_NOERRNO|APLOG_DEBUG, 0, r, \
                                  __VA_ARGS__)
#define IS_NULL_STR(str) (str == NULL || *str == '\0')

module AP_MODULE_DECLARE_DATA access_token_module;


typedef struct {
    apr_int64_t limited;
    int check;
    char *access_key;
    char *secret;
} access_token_config;

static char *hmac_sha1(apr_pool_t *p, char *data, char *key)
{
    apr_sha1_ctx_t context;
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    unsigned char k_ipad[65], k_opad[65];
    unsigned char kt[APR_SHA1_DIGESTSIZE];
    unsigned char *k = (unsigned char *)key;
    int key_len, i;
    char *out;
    int l, outlen;

    key_len = strlen(key);

    if(key_len > BLOCK_SIZE) {
        k = kt;
        key_len = APR_SHA1_DIGESTSIZE;
    }

    memset((void *)k_ipad, 0, sizeof(k_ipad));
    memset((void *)k_opad, 0, sizeof(k_opad));
    memmove(k_ipad, k, key_len);
    memmove(k_opad, k, key_len);

    for (i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    apr_sha1_init(&context);
    apr_sha1_update_binary(&context, k_ipad, 64);
    apr_sha1_update_binary(&context, (const unsigned char *)data, strlen(data));
    apr_sha1_final(digest, &context);

    apr_sha1_init(&context);
    apr_sha1_update_binary(&context, k_opad, 64);
    apr_sha1_update_binary(&context, digest, sizeof(digest));
    apr_sha1_final(digest, &context);

    outlen = apr_base64_encode_len(sizeof(digest));
    out = apr_palloc(p, outlen);
    l = apr_base64_encode_binary(out, digest, sizeof(digest));
    out[l - 2] = '\0';

    return out; 
}

static void *access_token_create_dir_config(apr_pool_t *p, char *dummy)
{
    access_token_config *conf = 
        (access_token_config *)apr_pcalloc(p, sizeof(access_token_config));
    int i;
    conf->check = -1;
    conf->access_key = NULL;
    conf->secret = NULL;
    return (void *)conf;
}

static void *access_token_merge_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    access_token_config *new = apr_pcalloc(p, sizeof(access_token_config));
    access_token_config *base = (access_token_config *)basev;
    access_token_config *add = (access_token_config *)addv;

    new->check = (add->check != -1) ? add->check : base->check;
    new->access_key = add->access_key ? add->access_key : base->access_key;
    new->secret = add->secret ? add->secret : base->secret;
    return (void *)new;
}

static apr_status_t access_token_parse_args( request_rec *r, apr_table_t *params )
{
    const char *args = apr_pstrdup( r->pool, r->args );
    char *val;
    while(*args && (val = ap_getword(r->pool, &args, '&'))) {
        char *name = ap_getword_nc(r->pool, &val, '=');
        if(name != NULL && val != NULL) {
#if (AP_SERVER_MINORVERSION_NUMBER > 2)
            if(ap_unescape_url_keep2f(val, 1) == OK)
#else
            if(ap_unescape_url_keep2f(val) == OK)
#endif
                apr_table_set(params, name, val);
        }
    }
    return APR_SUCCESS;
}

static int check_access_token(request_rec *r)
{
    access_token_config *conf = 
        (access_token_config *)ap_get_module_config(r->per_dir_config, &access_token_module);
    apr_table_t *params = apr_table_make( r->pool, 3 );
    char *plain;
    const char *expires, *access_key, *sig;
    const char *check_sig;
    int method = r->method_number;
    apr_int64_t mmask = (AP_METHOD_BIT << method);

    if(conf->check != 1)
        return DECLINED;
    if(apr_table_get(r->subprocess_env, "no-token-check"))
        return DECLINED;

    if(IS_NULL_STR(conf->secret) || IS_NULL_STR(conf->access_key)) {
        ERR(r, "Configuration error. You MUST specify AccessTokenAccessKey and AccessTokenSecret");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!(mmask & conf->limited)) 
        return DECLINED;
    if (!r->args) 
        return HTTP_FORBIDDEN;
    access_token_parse_args( r, params );
    expires = apr_table_get( params, EXPIRES_NAME );
    access_key = apr_table_get( params, ACCESS_KEY_NAME );
    sig = apr_table_get( params, SIGNATURE_NAME );
    if( IS_NULL_STR(expires) || IS_NULL_STR(access_key) || IS_NULL_STR(sig) ) 
    {
        ERR(r, "Invalid request arguments %s=%s, %s=%s, %s=%s", ACCESS_KEY_NAME, access_key, EXPIRES_NAME, expires, SIGNATURE_NAME, sig);
        return HTTP_FORBIDDEN;
    }
    if( strcmp(access_key, conf->access_key) != 0 ) {
        ERR(r, "%s does not match. %s, %s", ACCESS_KEY_NAME, access_key, conf->access_key );
        return HTTP_FORBIDDEN;

    }

    if(apr_atoi64( expires ) < apr_time_sec( apr_time_now() )) {
        ERR(r, "Request has expired");
        return HTTP_FORBIDDEN;
    }
    plain = apr_psprintf(r->pool, "%s%s%s%s", r->method, r->uri, expires, access_key);
    check_sig = hmac_sha1(r->pool, plain, conf->secret);
    if(strcmp(sig, check_sig) == 0) {
        DBG(r, "Signature OK: %s => %s:%s", plain, check_sig, sig);
        return OK;
    }
    else {
        ERR(r, "Invalid signature: %s => %s:%s", plain, check_sig, sig);
        return HTTP_FORBIDDEN;
    }
}

static void access_token_register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(check_access_token,NULL,NULL,APR_HOOK_MIDDLE);
}

static const char *access_token_set_check(cmd_parms *cmd, void *c, int v)
{
    access_token_config *conf = (access_token_config *)c;
    int i;
    conf->check = v;
    conf->limited = cmd->limited;
    return NULL;
}

static const command_rec access_token_cmds[] = {
    AP_INIT_TAKE1("AccessTokenAccessKey", ap_set_string_slot, 
                  (void *)APR_OFFSETOF(access_token_config, access_key),
                  OR_LIMIT, "set access token access_key value"),
    AP_INIT_TAKE1("AccessTokenSecret", ap_set_string_slot, 
                  (void *)APR_OFFSETOF(access_token_config, secret),
                  OR_LIMIT, "set access token secret value"),
    AP_INIT_FLAG("AccessTokenCheck", access_token_set_check, 
                 NULL,
                 OR_LIMIT, "check access token or NOT"),
    { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA access_token_module = {
    STANDARD20_MODULE_STUFF, 
    access_token_create_dir_config, /* create per-dir    config structures */
    NULL,                   /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    access_token_cmds,     /* table of config file commands       */
    access_token_register_hooks  /* register hooks                      */
};

