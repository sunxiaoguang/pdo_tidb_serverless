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
#include "pdo/php_pdo.h"
#include "pdo/php_pdo_driver.h"
#include "php_pdo_tidb_serverless.h"
#include "php_pdo_tidb_serverless_int.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"
#include "utf8proc.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof(X[0]))
#define TIDB_SERVERLESS_LAUNCH_TIME (1667232000)

static zend_string *zstr_begin;
static zend_string *zstr_commit;
static zend_string *zstr_rollback;
static zend_string *zstr_select_version;
static zend_string *zstr_show_sql_mode;

void tidb_serverless_driver_init()
{
  REGISTER_STRING2(begin, "BEGIN");
  REGISTER_STRING2(commit, "COMMIT");
  REGISTER_STRING2(rollback, "ROLLBACK");
  REGISTER_STRING2(select_version, "SELECT version()");
  REGISTER_STRING2(show_sql_mode, "SHOW VARIABLES LIKE 'sql_mode'");
}

void tidb_serverless_driver_shutdown()
{
  zend_string_release(zstr_begin);
  zend_string_release(zstr_commit);
  zend_string_release(zstr_rollback);
  zend_string_release(zstr_select_version);
  zend_string_release(zstr_show_sql_mode);
}

int32_t _pdo_tidb_serverless_error(pdo_tidb_serverless_db_handle *handle, pdo_tidb_serverless_stmt *stmt, uint32_t errcode, const char *file, int32_t line)
{
  pdo_dbh_t *dbh = handle->pdo;
  pdo_error_type *pdo_err;
  pdo_tidb_serverless_error_info *einfo;

  pdo_err = &dbh->error_code;
  einfo = &handle->einfo;

  einfo->file = file;
  einfo->line = line;
  einfo->errcode = errcode;

  // Serverless driver not support SQLSTATE yet
  strcpy(*pdo_err, "08S01");

  if (!dbh->methods) {
    // Throw an exception in constructor.
    // We know pdo_throw_exception doesn't modify errmsg so we can simply cast and remove const
    pdo_throw_exception(einfo->errcode, (char *) tidb_serverless_errmsg(errcode), pdo_err);
  }

  return einfo->errcode;
}

static void pdo_tidb_serverless_fetch_error_func(pdo_dbh_t *dbh, pdo_stmt_t *stmt, zval *info)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  pdo_tidb_serverless_error_info *einfo = &handle->einfo;

  if (einfo->errcode) {
    add_next_index_long(info, einfo->errcode);
    add_next_index_string(info, tidb_serverless_errmsg(einfo->errcode));
  }
  return;
}

static void tidb_serverless_handle_closer(pdo_dbh_t *dbh)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;

  if (handle) {
    if (handle->zstr_username) zend_string_release_ex(handle->zstr_username, dbh->is_persistent);
    if (handle->zstr_password) zend_string_release_ex(handle->zstr_password, dbh->is_persistent);
    if (handle->zstr_url) zend_string_release_ex(handle->zstr_url, dbh->is_persistent);
    if (handle->zstr_connection_status) zend_string_release_ex(handle->zstr_connection_status, dbh->is_persistent);
    if (handle->zstr_header_database) zend_string_release_ex(handle->zstr_header_database, dbh->is_persistent);
    if (handle->zstr_header_session) zend_string_release_ex(handle->zstr_header_session, dbh->is_persistent);
    if (handle->zstr_server_version) zend_string_release_ex(handle->zstr_server_version, dbh->is_persistent);
    pdo_tidb_serverless_free_result(&handle->last_result, dbh->is_persistent);
    pefree(handle, dbh->is_persistent);
    dbh->driver_data = NULL;
  }
}

static bool tidb_serverless_handle_preparer(pdo_dbh_t *dbh, zend_string *sql, pdo_stmt_t *stmt, zval *driver_options)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  pdo_tidb_serverless_stmt *s = ecalloc(1, sizeof(pdo_tidb_serverless_stmt));

  s->handle = handle;
  stmt->driver_data = s;
  stmt->methods = &tidb_serverless_stmt_methods;
  stmt->supports_placeholders = PDO_PLACEHOLDER_NONE;
  return true;
}

static zend_long tidb_serverless_handle_doer(pdo_dbh_t *dbh, const zend_string *sql)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  zend_result zres;

  TIDB_SERVERLESS_DO_GOTO(zres, cleanup_exit, tidb_serverless_db_execute(handle, sql, &handle->last_result));
  if (handle->last_result) {
    return handle->last_result->rows_affected;
  }

cleanup_exit:
  return TIDB_SERVERLESS_FAILED(zres) ? -1 : 0;
}

static zend_string *pdo_tidb_serverless_last_insert_id(pdo_dbh_t *dbh, const zend_string *name)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  return zend_u64_to_str(handle->last_result ? handle->last_result->last_insert_id : 0);
}

static ssize_t tidb_serverless_escape_quotes(const char *f, size_t from_length, char *t, size_t to_length)
{
  utf8proc_int32_t code;
  utf8proc_ssize_t size;
  const utf8proc_uint8_t *from = (const utf8proc_uint8_t *) f;
  utf8proc_uint8_t *to = (utf8proc_uint8_t *) t;
  const utf8proc_uint8_t *start = to;
  const utf8proc_uint8_t *end = from + from_length;

  while (from < end) {
    size = utf8proc_iterate(from, end - from, &code);
    if (size < 0) {
      return -1;
    }
    from += size;
    if (code == '\'') {
      memset(to, '\'', 2);
      to += 2;
    } else {
      size = utf8proc_encode_char(code, to);
      to += size;
    }
  }
  return to - start;
}

static ssize_t tidb_serverless_escape_string(const char *f, size_t from_length, char *t, size_t to_length)
{
  utf8proc_int32_t code;
  utf8proc_ssize_t size;
  const utf8proc_uint8_t *from = (const utf8proc_uint8_t *) f;
  utf8proc_uint8_t *to = (utf8proc_uint8_t *) t;
  const utf8proc_uint8_t *start = to;
  const utf8proc_uint8_t *end = from + from_length;
  char escape;

  while (from < end) {
    size = utf8proc_iterate(from, end - from, &code);
    if (size < 0) {
      return -1;
    }
    from += size;
    escape = 0;
    switch (code) {
      case 0:
        escape = '0';
        break;
      case '\n':
        escape = 'n';
        break;
      case '\r':
        escape = 'r';
        break;
      case '\032':
        escape = 'Z';
        break;
      case '\\':
        escape = '\\';
        break;
      case '\'':
        escape = '\'';
        break;
      case '"':
        escape = '"';
        break;
    }
    if (escape != 0) {
      *to++ = '\\';
      *to++ = escape;
    } else {
      size = utf8proc_encode_char(code, to);
      to += size;
    }
  }
  return to - start;
}

static zend_string *tidb_serverless_handle_quoter(pdo_dbh_t *dbh, const zend_string *unquoted, enum pdo_param_type paramtype)
{
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  char *buffer;
  size_t quoted_len;
  zend_string *quoted_str = NULL;

  buffer = safe_emalloc(2, ZSTR_LEN(unquoted), 3);
  buffer[0] = '\'';
  if (handle->no_backslash_escapes) {
    quoted_len = tidb_serverless_escape_quotes(ZSTR_VAL(unquoted), ZSTR_LEN(unquoted), buffer + 1, 2 * ZSTR_LEN(unquoted));
  } else {
    quoted_len = tidb_serverless_escape_string(ZSTR_VAL(unquoted), ZSTR_LEN(unquoted), buffer + 1, 2 * ZSTR_LEN(unquoted));
  }
  if (quoted_len == -1) {
    pdo_tidb_serverless_error(handle, ERR_INVALID_UTF8MB4_ENCODING);
    goto cleanup_exit;
  }
  buffer[++quoted_len] = '\'';
  buffer[++quoted_len] = '\0';

  quoted_str = zend_string_init(buffer, quoted_len, 0);
cleanup_exit:
  efree(buffer);
  return quoted_str;
}

static void tidb_serverless_handle_reset_session(pdo_tidb_serverless_db_handle *handle)
{
  if (handle->zstr_header_session) {
    zend_string_release(handle->zstr_header_session);
    handle->zstr_header_session = NULL;
  }
}

static bool tidb_serverless_handle_begin(pdo_dbh_t *dbh)
{
  pdo_tidb_serverless_result *rs = NULL;
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;

  if (handle->in_transaction) {
    return false;
  }
  tidb_serverless_handle_reset_session(handle);
  if (TIDB_SERVERLESS_FAILED(tidb_serverless_db_execute(handle, zstr_begin, &rs)))  {
    return false;
  }
  handle->in_transaction = true;
  return true;
}

static bool tidb_serverless_handle_commit(pdo_dbh_t *dbh)
{
  pdo_tidb_serverless_result *rs = NULL;
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  if (!handle->in_transaction) {
    return false;
  }
  if (TIDB_SERVERLESS_FAILED(tidb_serverless_db_execute(dbh->driver_data, zstr_commit, &rs))) {
    return false;
  }
  tidb_serverless_handle_reset_session(handle);
  handle->in_transaction = false;
  return true;
}

static bool tidb_serverless_handle_rollback(pdo_dbh_t *dbh)
{
  pdo_tidb_serverless_result *rs = NULL;
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;
  if (TIDB_SERVERLESS_FAILED(tidb_serverless_db_execute(handle, zstr_rollback, &rs))) {
    return false;
  }
  tidb_serverless_handle_reset_session(handle);
  handle->in_transaction = false;
  return true;
}

static bool pdo_tidb_serverless_set_attribute(pdo_dbh_t *dbh, zend_long attr, zval *val)
{
  bool bval;

  switch (attr) {
    case PDO_ATTR_AUTOCOMMIT:
      if (!pdo_get_bool_param(&bval, val)) {
        return false;
      }
      dbh->auto_commit = bval;
      return true;

    default:
      return false;
  }
}

static int32_t pdo_tidb_serverless_get_attribute(pdo_dbh_t *dbh, zend_long attr, zval *return_value)
{
  char buffer[256];
  pdo_tidb_serverless_db_handle *handle = (pdo_tidb_serverless_db_handle *)dbh->driver_data;

  switch (attr) {
    case PDO_ATTR_CLIENT_VERSION:
      ZVAL_STRING(return_value, (char *) PHP_PDO_TIDB_SERVERLESS_VERSION);
      break;

    case PDO_ATTR_SERVER_VERSION:
      ZVAL_STR_COPY(return_value, handle->zstr_server_version);
      break;

    case PDO_ATTR_CONNECTION_STATUS:
      ZVAL_STR_COPY(return_value, handle->zstr_connection_status);
      break;

    case PDO_ATTR_SERVER_INFO: {
      snprintf(buffer, sizeof(buffer), "Uptime: %ld Threads: 0  Questions: 0  Slow queries: 0  Opens: 0  Flush tables: 0  Open tables: 0  Queries per second avg: 0.000", (int64_t)(time(NULL) - TIDB_SERVERLESS_LAUNCH_TIME));
      ZVAL_STRING(return_value, buffer);
      break;
    }
    break;

    case PDO_ATTR_AUTOCOMMIT:
      ZVAL_LONG(return_value, dbh->auto_commit);
      break;

    default:
      return 0;
  }

  return 1;
}

static zend_result pdo_tidb_serverless_check_liveness(pdo_dbh_t *dbh)
{
  return SUCCESS;
}

static void pdo_tidb_serverless_request_shutdown(pdo_dbh_t *dbh)
{
}

static bool pdo_tidb_serverless_in_transaction(pdo_dbh_t *dbh)
{
  return ((pdo_tidb_serverless_db_handle *)dbh->driver_data)->in_transaction;
}

static const struct pdo_dbh_methods tidb_serverless_methods = {
  tidb_serverless_handle_closer,
  tidb_serverless_handle_preparer,
  tidb_serverless_handle_doer,
  tidb_serverless_handle_quoter,
  tidb_serverless_handle_begin,
  tidb_serverless_handle_commit,
  tidb_serverless_handle_rollback,
  pdo_tidb_serverless_set_attribute,
  pdo_tidb_serverless_last_insert_id,
  pdo_tidb_serverless_fetch_error_func,
  pdo_tidb_serverless_get_attribute,
  pdo_tidb_serverless_check_liveness,
  NULL,
  pdo_tidb_serverless_request_shutdown,
  pdo_tidb_serverless_in_transaction,
  NULL /* get_gc */
};

static int32_t pdo_tidb_serverless_handle_factory(pdo_dbh_t *dbh, zval *driver_options)
{
  pdo_tidb_serverless_db_handle *handle;
  size_t i;
  int32_t ret = 0;
  zend_result zres;
  pdo_tidb_serverless_result *rs = NULL;
  struct pdo_data_src_parser vars[] = {
    {"dbname", "", 0},
    {"host", "localhost", 0},
    {"user", NULL, 0},
    {"password", NULL, 0},
  };
  char *sql_mode_string = NULL, *sql_mode = NULL;
  smart_str url_str = {0};

  php_pdo_parse_data_source(dbh->data_source, dbh->data_source_len, vars, ARRAY_SIZE(vars));

  if (dbh->username == NULL && vars[2].optval == NULL) {
    return 0;
  }
  if (dbh->password == NULL && vars[3].optval == NULL) {
    return 0;
  }

  handle = pecalloc(1, sizeof(pdo_tidb_serverless_db_handle), dbh->is_persistent);

  dbh->driver_data = handle;

  smart_str_appendl_ex(&url_str, STRING_LITERAL_ARGS("TiDB-Database: "), dbh->is_persistent);
  smart_str_appends_ex(&url_str, vars[0].optval, dbh->is_persistent);
  handle->zstr_header_database = smart_str_extract(&url_str);
  handle->zstr_username = dbh->username ? zend_string_init(dbh->username, strlen(dbh->username), dbh->is_persistent) : zend_string_init(vars[2].optval, strlen(vars[2].optval), dbh->is_persistent);
  handle->zstr_password = dbh->password ? zend_string_init(dbh->password, strlen(dbh->password), dbh->is_persistent) : zend_string_init(vars[3].optval, strlen(vars[3].optval), dbh->is_persistent);
  smart_str_appendl_ex(&url_str, STRING_LITERAL_ARGS("https://http-"), dbh->is_persistent);
  smart_str_appends_ex(&url_str, vars[1].optval, dbh->is_persistent);
  smart_str_appendl_ex(&url_str, STRING_LITERAL_ARGS("/v1beta/sql"), dbh->is_persistent);
  handle->zstr_url = smart_str_extract(&url_str);
  smart_str_appends_ex(&url_str, vars[1].optval, dbh->is_persistent);
  smart_str_appendl_ex(&url_str, STRING_LITERAL_ARGS(" via HTTPS"), dbh->is_persistent);
  handle->zstr_connection_status = smart_str_extract(&url_str);
  handle->pdo = dbh;

  dbh->alloc_own_columns = 1;
  dbh->max_escaped_char_length = 2;
  dbh->methods = &tidb_serverless_methods;

  // fetch server version
  TIDB_SERVERLESS_DO_GOTO(zres, cleanup_exit, tidb_serverless_db_execute(handle, zstr_select_version, &rs));
  handle->zstr_server_version = zend_string_init(rs->rows[0][0], strlen(rs->rows[0][0]), dbh->is_persistent);
  pdo_tidb_serverless_free_result(&rs, dbh->is_persistent);

  TIDB_SERVERLESS_DO_GOTO(zres, cleanup_exit, tidb_serverless_db_execute(handle, zstr_show_sql_mode, &rs));
  sql_mode_string = rs->rows[0][1];
  while ((sql_mode = strsep(&sql_mode_string, ",")) != NULL) {
    if (strcasecmp(sql_mode, "NO_BACKSLASH_ESCAPES") == 0) {
      handle->no_backslash_escapes = true;
      break;
    }
  }
  pdo_tidb_serverless_free_result(&rs, dbh->is_persistent);

  ret = 1;

cleanup_exit:
  for (i = 0; i < ARRAY_SIZE(vars); i++) {
    if (vars[i].freeme) {
      efree(vars[i].optval);
    }
  }

  dbh->methods = &tidb_serverless_methods;

  return ret;
}

const pdo_driver_t pdo_tidb_serverless_driver = {
  PDO_DRIVER_HEADER(tidb_serverless),
  pdo_tidb_serverless_handle_factory
};
