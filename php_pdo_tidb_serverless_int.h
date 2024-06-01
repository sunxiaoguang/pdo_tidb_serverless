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

#ifndef PHP_PDO_TIDB_SERVERLESS_INT_H
#define PHP_PDO_TIDB_SERVERLESS_INT_H

#include <stdint.h>
#include <stdbool.h>

ZEND_BEGIN_MODULE_GLOBALS(pdo_tidb_serverless)
void* dummy;
ZEND_END_MODULE_GLOBALS(pdo_tidb_serverless)

ZEND_EXTERN_MODULE_GLOBALS(pdo_tidb_serverless)
#define PDO_TIDB_SERVERLESS_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(pdo_tidb_serverless, v)

#if defined(ZTS) && defined(COMPILE_DL_PDO_TIDB_SERVERLESS)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

typedef struct pdo_tidb_serverless_result pdo_tidb_serverless_result;

typedef struct
{
  const char *file;
  int32_t line;
  uint32_t errcode;
} pdo_tidb_serverless_error_info;

/* stuff we use in a database handle */
typedef struct
{
  pdo_dbh_t *pdo;

  bool in_transaction;

  zend_string *zstr_username;
  zend_string *zstr_password;
  zend_string *zstr_url;
  zend_string *zstr_connection_status;
  zend_string *zstr_header_database;
  zend_string *zstr_header_session;
  zend_string *zstr_server_version;

  bool no_backslash_escapes;
  pdo_tidb_serverless_result *last_result;

  pdo_tidb_serverless_error_info einfo;
} pdo_tidb_serverless_db_handle;

typedef struct
{
  char *name;
  char *type;
  int32_t nullable;
} pdo_tidb_serverless_column;

typedef char *pdo_tidb_serverless_field;
typedef pdo_tidb_serverless_field *pdo_tidb_serverless_result_row;

typedef struct pdo_tidb_serverless_result
{
  pdo_tidb_serverless_column *columns;
  pdo_tidb_serverless_result_row *rows;
  size_t rows_count;
  size_t columns_count;
  int64_t rows_affected;
  int64_t last_insert_id;
  char *session;
} pdo_tidb_serverless_result;

typedef struct
{
  pdo_tidb_serverless_db_handle *handle;
  pdo_tidb_serverless_result *last_result;
  off_t current_row;
} pdo_tidb_serverless_stmt;

extern const pdo_driver_t pdo_tidb_serverless_driver;

extern int32_t _pdo_tidb_serverless_error(pdo_tidb_serverless_db_handle *handle, pdo_tidb_serverless_stmt *stmt, uint32_t errcode, const char *file, int32_t line);
#define pdo_tidb_serverless_error(s, c) _pdo_tidb_serverless_error((s), NULL, (c), __FILE__, __LINE__)
#define pdo_tidb_serverless_error_stmt(s, c) _pdo_tidb_serverless_error((s)->handle, s, (c), __FILE__, __LINE__)

extern const struct pdo_stmt_methods tidb_serverless_stmt_methods;

extern zend_result tidb_serverless_db_execute(pdo_tidb_serverless_db_handle *handle, const zend_string *sql, pdo_tidb_serverless_result **result);
extern void pdo_tidb_serverless_free_result(pdo_tidb_serverless_result **result, bool is_persistent);
extern void tidb_serverless_protocol_init();
extern void tidb_serverless_protocol_shutdown();
extern void tidb_serverless_driver_init();
extern void tidb_serverless_driver_shutdown();

#define STRING_LITERAL_LENGTH(x) sizeof(x) - 1
#define STRING_LITERAL_ARGS(x) x, STRING_LITERAL_LENGTH(x)
#define REGISTER_STRING2(x, y) do {                         \
    zstr_##x = zend_string_init(STRING_LITERAL_ARGS(y), 1); \
    zend_string_hash_val(zstr_##x);                         \
    GC_ADD_FLAGS(zstr_##x, IS_STR_INTERNED);                \
  } while (0)
#define REGISTER_STRING(x) REGISTER_STRING2(x, #x)
#define TIDB_SERVERLESS_FAILED(x) (FAILURE == (x))
#define TIDB_SERVERLESS_DO(res, x)                                        \
{                                                                         \
  if (TIDB_SERVERLESS_FAILED(res = (x))) {                                \
    return res;                                                           \
  }                                                                       \
}
#define TIDB_SERVERLESS_DO_RETURN(res, x)                                 \
{                                                                         \
  if (TIDB_SERVERLESS_FAILED((x))) {                                      \
    return res;                                                           \
  }                                                                       \
}
#define TIDB_SERVERLESS_DO_GOTO(res, cleanup_exit, x)                     \
{                                                                         \
  if (TIDB_SERVERLESS_FAILED(res = (x))) {                                \
    goto cleanup_exit;                                                    \
  }                                                                       \
}

#define ERR_NO_ERROR 0
#define ERR_NO_RESULT_SET 2053
#define ERR_INVALID_PARAMETER_NO 2034
#define ERR_INVALID_UTF8MB4_ENCODING 2074

extern const char *tidb_serverless_errmsg(uint32_t code);

#endif
