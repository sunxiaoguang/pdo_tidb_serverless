// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "pdo/php_pdo.h"
#include "pdo/php_pdo_driver.h"
#include "php_pdo_tidb_serverless.h"
#include "php_pdo_tidb_serverless_int.h"
#include "zend_smart_str.h"

#define TIDB_SESSION_HEADER "TiDB-Session: "

static zend_string *zstr_curl_init;
static zend_string *zstr_curl_setopt;
static zend_string *zstr_curl_exec;
static zend_string *zstr_curl_getinfo;
static zend_string *zstr_substr;
static zend_string *zstr_json_encode;
static zend_string *zstr_json_decode;
static zend_string *zstr_types;
static zend_string *zstr_rows;
static zend_string *zstr_rows_affected;
static zend_string *zstr_last_insert_id;
static zend_string *zstr_type;
static zend_string *zstr_name;
static zend_string *zstr_nullable;
static zend_string *zstr_curlopt_returntransfer;
static zend_string *zstr_curlopt_post;
static zend_string *zstr_curlopt_header;
static zend_string *zstr_curlopt_username;
static zend_string *zstr_curlopt_password;
static zend_string *zstr_curlopt_url;
static zend_string *zstr_curlopt_httpheader;
static zend_string *zstr_curlopt_postfields;
static zend_string *zstr_curlinfo_header_size;
static zend_string *zstr_curlinfo_http_code;
static zend_string *zstr_content_type;
static zend_string *zstr_user_agent;
static zend_string *zstr_query;

void tidb_serverless_protocol_init()
{
  REGISTER_STRING(curl_init);
  REGISTER_STRING(curl_setopt);
  REGISTER_STRING(curl_exec);
  REGISTER_STRING(curl_getinfo);
  REGISTER_STRING(substr);
  REGISTER_STRING(json_encode);
  REGISTER_STRING(json_decode);
  REGISTER_STRING(types);
  REGISTER_STRING(rows);
  REGISTER_STRING2(rows_affected, "rowsAffected");
  REGISTER_STRING2(last_insert_id, "lastInsertId");
  REGISTER_STRING(type);
  REGISTER_STRING(name);
  REGISTER_STRING(nullable);
  REGISTER_STRING2(curlopt_returntransfer, "CURLOPT_RETURNTRANSFER");
  REGISTER_STRING2(curlopt_post, "CURLOPT_POST");
  REGISTER_STRING2(curlopt_header, "CURLOPT_HEADER");
  REGISTER_STRING2(curlopt_username, "CURLOPT_USERNAME");
  REGISTER_STRING2(curlopt_password, "CURLOPT_PASSWORD");
  REGISTER_STRING2(curlopt_url, "CURLOPT_URL");
  REGISTER_STRING2(curlopt_httpheader, "CURLOPT_HTTPHEADER");
  REGISTER_STRING2(curlopt_postfields, "CURLOPT_POSTFIELDS");
  REGISTER_STRING2(curlinfo_header_size, "CURLINFO_HEADER_SIZE");
  REGISTER_STRING2(curlinfo_http_code, "CURLINFO_HTTP_CODE");
  REGISTER_STRING2(content_type, "Content-Type: application/json");
  REGISTER_STRING2(user_agent, "User-Agent: serverless-php/0.0.10");
  REGISTER_STRING(query);
}

void tidb_serverless_protocol_shutdown()
{
  zend_string_release(zstr_curl_init);
  zend_string_release(zstr_curl_setopt);
  zend_string_release(zstr_curl_exec);
  zend_string_release(zstr_curl_getinfo);
  zend_string_release(zstr_substr);
  zend_string_release(zstr_json_encode);
  zend_string_release(zstr_json_decode);
  zend_string_release(zstr_types);
  zend_string_release(zstr_rows);
  zend_string_release(zstr_rows_affected);
  zend_string_release(zstr_last_insert_id);
  zend_string_release(zstr_type);
  zend_string_release(zstr_name);
  zend_string_release(zstr_nullable);
  zend_string_release(zstr_curlopt_returntransfer);
  zend_string_release(zstr_curlopt_post);
  zend_string_release(zstr_curlopt_header);
  zend_string_release(zstr_curlopt_username);
  zend_string_release(zstr_curlopt_password);
  zend_string_release(zstr_curlopt_url);
  zend_string_release(zstr_curlopt_httpheader);
  zend_string_release(zstr_curlopt_postfields);
  zend_string_release(zstr_curlinfo_header_size);
  zend_string_release(zstr_curlinfo_http_code);
  zend_string_release(zstr_content_type);
  zend_string_release(zstr_user_agent);
}

zend_result call_user_function_helper(zend_string *function, zval *params, size_t num_params, zval *response)
{
  zval fname, zret;
  zend_result result = SUCCESS;
  ZVAL_INTERNED_STR(&fname, function);
  ZVAL_UNDEF(&zret);

  if (response == NULL) {
    response = &zret;
  }

  if (TIDB_SERVERLESS_FAILED(result = call_user_function(NULL, NULL, &fname, response, num_params, params))) {
    if (!EG(exception)) {
      zend_throw_exception_ex(NULL, 0, "Failed calling %s", ZSTR_VAL(function));
    }
    goto cleanup_exit;
  }
  if (EG(exception)) {
    result = FAILURE;
  }
cleanup_exit:
  if (response == &zret) {
    // caller doesn't care response, destroy the result
    zval_ptr_dtor(&zret);
  }
  zval_ptr_dtor(&fname);
  return result;
}

zend_result call_curl_init(zval *handle)
{
  return call_user_function_helper(zstr_curl_init, NULL, 0, handle);
}

zend_result call_curl_setopt(zval *handle, zend_string *opt_name, zval *opt_value)
{
  zval params[3];
  zend_result zres;

  ZVAL_COPY_VALUE(params, handle);
  ZVAL_COPY_VALUE(params + 1, zend_get_constant(opt_name));
  ZVAL_COPY_VALUE(params + 2, opt_value);
  zres = call_user_function_helper(zstr_curl_setopt, params, 3, NULL);

  zval_ptr_dtor(params + 1);
  return zres;
}

zend_result call_curl_exec(zval *handle, zval *response)
{
  return call_user_function_helper(zstr_curl_exec, handle, 1, response);
}

zend_result call_curl_getinfo(zval *handle, zend_string *info_name, zval *info_value)
{
  zval params[2];

  ZVAL_COPY_VALUE(params, handle);
  ZVAL_COPY_VALUE(params + 1, zend_get_constant(info_name));
  return call_user_function_helper(zstr_curl_getinfo, params, 2, info_value);
}

zend_result call_split_str(zval *str, zval *at, zval *left, zval *right)
{
  zval params[3];
  zend_result result;

  memset(params, 0, sizeof(params));
  ZVAL_COPY_VALUE(params, str);
  ZVAL_LONG(params + 1, 0);
  ZVAL_COPY_VALUE(params + 2, at);
  TIDB_SERVERLESS_DO(result, call_user_function_helper(zstr_substr, params, 3, left));
  ZVAL_COPY_VALUE(params + 1, at);
  return call_user_function_helper(zstr_substr, params, 2, right);
}

zend_result serialize_body(zval *json, const zend_string *sql)
{
  zval zsql, zarray;
  zend_result result;
  HashTable *zbody = zend_new_array(1);
  ZVAL_STR_COPY(&zsql, (zend_string*) sql);
  zend_hash_add_new(zbody, zstr_query, &zsql);
  ZVAL_ARR(&zarray, zbody);

  result = call_user_function_helper(zstr_json_encode, &zarray, 1, json);

  zval_ptr_dtor(&zarray);

  return result;
}

zend_result deserialize_response(zval *response, zval *object)
{
  return call_user_function_helper(zstr_json_decode, response, 1, object);
}

static void populate_types_from_zval(zval *ztypes, pdo_tidb_serverless_result *result, bool is_persistent)
{
  zval *zitem, *zname, *ztype, *znullable;
  zend_class_entry *ce = NULL;
  zend_object *obj = NULL;
  zend_ulong idx;
  HashTable *types = Z_ARRVAL_P(ztypes);
  result->columns_count = zend_hash_num_elements(types);
  result->columns = pecalloc(sizeof(pdo_tidb_serverless_column), result->columns_count, is_persistent);

  ZEND_HASH_FOREACH_NUM_KEY_VAL(types, idx, zitem) {
    if (ce == NULL) {
      ce = Z_OBJCE_P(zitem);
    }
    obj = Z_OBJ_P(zitem);
    if ((ztype = zend_read_property_ex(ce, obj, zstr_type, true, NULL))) {
      result->columns[idx].type = pestrndup(Z_STRVAL_P(ztype), Z_STRLEN_P(ztype), is_persistent);
    }
    if ((zname = zend_read_property_ex(ce, obj, zstr_name, true, NULL))) {
      result->columns[idx].name = pestrndup(Z_STRVAL_P(zname), Z_STRLEN_P(zname), is_persistent);
    }
    if ((znullable = zend_read_property_ex(ce, obj, zstr_nullable, true, NULL))) {
      result->columns[idx].nullable = Z_TYPE_P(znullable) == IS_TRUE;
    }
  } ZEND_HASH_FOREACH_END();
}

static void populate_rows_from_zval(zval *zrows, pdo_tidb_serverless_result *result, bool is_persistent)
{
  zval *zitem;
  HashTable *row, *rows = Z_ARRVAL_P(zrows);
  zend_ulong idx, fidx;

  result->rows_count = zend_hash_num_elements(rows);
  result->rows = pecalloc(sizeof(pdo_tidb_serverless_result_row), result->rows_count, is_persistent);

  ZEND_HASH_FOREACH_NUM_KEY_VAL(rows, idx, zitem) {
    row = Z_ARRVAL_P(zitem);
    result->rows[idx] = pecalloc(sizeof(pdo_tidb_serverless_field), result->columns_count, is_persistent);
    ZEND_HASH_FOREACH_NUM_KEY_VAL(row, fidx, zitem) {
      if (Z_TYPE_P(zitem) != IS_NULL) {
        result->rows[idx][fidx] = pestrndup(Z_STRVAL_P(zitem), Z_STRLEN_P(zitem), is_persistent);
      }
    } ZEND_HASH_FOREACH_END();
  } ZEND_HASH_FOREACH_END();
}

static void populate_types_and_rows_from_zval(zend_class_entry *ce, zend_object *obj, pdo_tidb_serverless_result *result, bool is_persistent)
{
  zval *ztypes = zend_read_property_ex(ce, obj, zstr_types, true, NULL);
  zval *zrows = zend_read_property_ex(ce, obj, zstr_rows, true, NULL);

  if (!ztypes || Z_TYPE_P(ztypes) == IS_NULL) {
    return;
  }
  populate_types_from_zval(ztypes, result, is_persistent);

  if (!zrows || Z_TYPE_P(zrows) == IS_NULL) {
    return;
  }
  populate_rows_from_zval(zrows, result, is_persistent);
}

static void populate_rows_affected_from_zval(zend_class_entry *ce, zend_object *obj, pdo_tidb_serverless_result *result)
{
  zval *affected = zend_read_property_ex(ce, obj, zstr_rows_affected, true, NULL);
  if (affected) {
    result->rows_affected = Z_LVAL_P(affected);
  } else {
    result->rows_affected = -1;
  }
}

static void populate_last_insert_id_from_zval(zend_class_entry *ce, zend_object *obj, pdo_tidb_serverless_result *result)
{
  zval *last_id = zend_read_property_ex(ce, obj, zstr_last_insert_id, true, NULL);
  if (last_id) {
    result->last_insert_id = Z_LVAL_P(last_id);
  } else {
    result->last_insert_id = -1;
  }
}

static zend_result populate_resultset_from_zval(zval *object, pdo_tidb_serverless_result *result, bool is_persistent)
{
  zend_class_entry *ce = Z_OBJCE_P(object);
  zend_object *obj = Z_OBJ_P(object);

  populate_types_and_rows_from_zval(ce, obj, result, is_persistent);
  populate_rows_affected_from_zval(ce, obj, result);
  populate_last_insert_id_from_zval(ce, obj, result);

  return SUCCESS;
}

static zend_result extract_session_if_any(zval *headers, zend_string **session, bool is_persistent)
{
  char *session_header = NULL;
  char *session_start = NULL;
  char *session_end = NULL;
  smart_str new_session = {0};

  if (Z_TYPE_P(headers) != IS_STRING) {
    zend_throw_exception_ex(NULL, 0, "Invalid response headers");
    return FAILURE;
  }

  if ((session_header = strcasestr(Z_STRVAL_P(headers), "tidb-session: ")) != NULL) {
    // extract session out
    session_start = session_header + strlen("tidb-session: ");
    if ((session_end = strchr(session_start, '\r')) == NULL ||
      (session_end = strchr(session_start, '\n')) == NULL) {
      session_end = session_start + strlen(session_start);
    } else {
      session_end -= 1;
    }

    char buffer[128];
    memcpy(buffer, session_start, session_end - session_start);
    buffer[session_end - session_start] = 0;

    if (*session == NULL || strncmp(ZSTR_VAL(*session) + STRING_LITERAL_LENGTH(TIDB_SESSION_HEADER), session_start, session_end - session_start) != 0) {
      if (*session) {
        zend_string_release(*session);
      }
      smart_str_appendl_ex(&new_session, STRING_LITERAL_ARGS(TIDB_SESSION_HEADER), is_persistent);
      smart_str_appendl_ex(&new_session, session_start, session_end - session_start, is_persistent);
      *session = smart_str_extract(&new_session);
    }
  }

  return SUCCESS;
}

static zend_result execute_query(pdo_tidb_serverless_db_handle *handle, zval *headers, zend_string *url, zend_string *username, zend_string *password, const zend_string *sql, zend_string **session, pdo_tidb_serverless_result **rs)
{
  zval ch, t, zurl, zusername, zpassword, zresponse, zbody;
  zval zhttp_code, zresponse_headers, zresponse_headers_length, zresponse_body, zresponse_object;
  zend_result result = SUCCESS;
  ZVAL_STR_COPY(&zusername, username);
  ZVAL_STR_COPY(&zpassword, password);
  ZVAL_STR_COPY(&zurl, url);
  ZVAL_UNDEF(&zresponse);
  ZVAL_UNDEF(&zresponse_headers);
  ZVAL_UNDEF(&zresponse_headers_length);
  ZVAL_UNDEF(&zresponse_body);
  ZVAL_UNDEF(&zresponse_object);

  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, serialize_body(&zbody, sql));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_init(&ch));
  ZVAL_TRUE(&t);
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_returntransfer, &t));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_post, &t));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_header, &t));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_username, &zusername));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_password, &zpassword));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_url, &zurl));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_httpheader, headers));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_setopt(&ch, zstr_curlopt_postfields, &zbody));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_exec(&ch, &zresponse));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_getinfo(&ch, zstr_curlinfo_http_code, &zhttp_code));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_curl_getinfo(&ch, zstr_curlinfo_header_size, &zresponse_headers_length));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, call_split_str(&zresponse, &zresponse_headers_length, &zresponse_headers, &zresponse_body));
  if (Z_LVAL(zhttp_code) < 200 || Z_LVAL(zhttp_code) >= 300) {
    zend_throw_exception_ex(NULL, 0, "Executing query failed: %s", Z_STRVAL(zresponse_body));
    result = FAILURE;
    goto cleanup_exit;
  }
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, extract_session_if_any(&zresponse_headers, session, handle->pdo->is_persistent));
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, deserialize_response(&zresponse_body, &zresponse_object));

  pdo_tidb_serverless_free_result(rs, handle->pdo->is_persistent);
  *rs = pecalloc(sizeof(pdo_tidb_serverless_result), 1, handle->pdo->is_persistent);
  TIDB_SERVERLESS_DO_GOTO(result, cleanup_exit, populate_resultset_from_zval(&zresponse_object, *rs, handle->pdo->is_persistent));

cleanup_exit:
  zval_ptr_dtor(&ch);
  zval_ptr_dtor(&t);
  zval_ptr_dtor(&zurl);
  zval_ptr_dtor(&zusername);
  zval_ptr_dtor(&zpassword);
  zval_ptr_dtor(&zresponse);
  zval_ptr_dtor(&zbody);
  zval_ptr_dtor(&zresponse_headers);
  zval_ptr_dtor(&zresponse_headers_length);
  zval_ptr_dtor(&zresponse_body);
  zval_ptr_dtor(&zresponse_object);

  if (TIDB_SERVERLESS_FAILED(result)) {
    pdo_tidb_serverless_free_result(rs, handle->pdo->is_persistent);
  }

  return result;
}

zend_result tidb_serverless_db_execute(pdo_tidb_serverless_db_handle *handle, const zend_string *sql, pdo_tidb_serverless_result **result)
{
  zval zheaders, zcontent_type, zuser_agent, zdatabase, zsession;
  zend_result zres;
  HashTable *headers = zend_new_array(4);

  ZVAL_INTERNED_STR(&zcontent_type, zstr_content_type);
  ZVAL_INTERNED_STR(&zuser_agent, zstr_user_agent);
  ZVAL_UNDEF(&zsession);
  ZVAL_STR_COPY(&zdatabase, handle->zstr_header_database);
  zend_hash_index_add_new(headers, 0, &zcontent_type);
  zend_hash_index_add_new(headers, 1, &zuser_agent);
  zend_hash_index_add_new(headers, 2, &zdatabase);
  if (handle->zstr_header_session) {
    ZVAL_STR_COPY(&zsession, handle->zstr_header_session);
    zend_hash_index_add_new(headers, 3, &zsession);
  }
  ZVAL_ARR(&zheaders, headers);

  zres = execute_query(handle, &zheaders, handle->zstr_url, handle->zstr_username, handle->zstr_password, sql, &handle->zstr_header_session, result);

  zval_ptr_dtor(&zheaders);

  return zres;
}

void pdo_tidb_serverless_free_result(pdo_tidb_serverless_result **r, bool is_persistent)
{
  size_t fidx, ridx;
  pdo_tidb_serverless_result *result = *r;
  if (!result) {
    return;
  }

  for (ridx = 0; ridx < result->rows_count; ++ridx) {
    for (fidx = 0; fidx < result->columns_count; ++fidx) {
      pefree(result->rows[ridx][fidx], is_persistent);
    }
    pefree(result->rows[ridx], is_persistent);
  }
  pefree(result->rows, is_persistent);
  for (fidx = 0; fidx < result->columns_count; ++fidx) {
    pefree(result->columns[fidx].type, is_persistent);
    pefree(result->columns[fidx].name, is_persistent);
  }
  pefree(result->columns, is_persistent);
  pefree(result, is_persistent);
  *r = NULL;
}

const char *tidb_serverless_errmsg(uint32_t code)
{
  switch (code) {
    case ERR_NO_ERROR:
      return NULL;
    case ERR_NO_RESULT_SET:
      return "Attempt to read a row while there is no result set associated with the statement";
    case ERR_INVALID_PARAMETER_NO:
      return "Invalid parameter number";
    case ERR_INVALID_UTF8MB4_ENCODING:
      return "Invalid utf8mb4 encoded string";
    default:
      return "Unknown error";
  }
}
