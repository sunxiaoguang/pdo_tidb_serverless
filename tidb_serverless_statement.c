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

#define CHECK_PRECONDITION(x, stmt, errcode, ret)     \
  if (!(x)) {                                         \
    pdo_tidb_serverless_error_stmt((stmt), errcode);  \
    return ret;                                       \
  }

static const char *INTEGER_TYPES[] = {
  "BIT",
  "YEAR",
  "TINYINT",
  "UNSIGNED TINYINT",
  "SMALLINT",
  "UNSIGNED SMALLINT",
  "MEDIUMINT",
  "UNSIGNED MEDIUMINT",
  "INT",
  "UNSIGNED INT",
  "BIGINT",
  "UNSIGNED BIGINT",
};

static int32_t pdo_tidb_serverless_stmt_dtor(pdo_stmt_t *stmt)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt*)stmt->driver_data;
  pdo_tidb_serverless_free_result(&handle->last_result, stmt->dbh->is_persistent);
  pefree(handle, stmt->dbh->is_persistent);
  return 1;
}

static int32_t pdo_tidb_serverless_fill_stmt_from_result(pdo_stmt_t *stmt)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *) stmt->driver_data;

  CHECK_PRECONDITION(handle->last_result, handle, ERR_NO_RESULT_SET, 0);

  if (handle->last_result->rows_affected == -1) {
    // DML with affected rows
    stmt->row_count = (zend_long) handle->last_result->rows_affected;
  } else {
    stmt->row_count = (zend_long) handle->last_result->rows_count;
    php_pdo_stmt_set_column_count(stmt, handle->last_result->columns_count);
    handle->current_row = -1;
  }
  return 1;
}

static int32_t pdo_tidb_serverless_stmt_execute(pdo_stmt_t *stmt)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;

  pdo_tidb_serverless_free_result(&handle->last_result, stmt->dbh->is_persistent);
  TIDB_SERVERLESS_DO_RETURN(0, tidb_serverless_db_execute(handle->handle, stmt->active_query_string, &handle->last_result));
  return pdo_tidb_serverless_fill_stmt_from_result(stmt);
}

static int32_t pdo_tidb_serverless_stmt_next_rowset(pdo_stmt_t *stmt)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;

  /* ensure that we free any previous unfetched results */
  pdo_tidb_serverless_free_result(&handle->last_result, stmt->dbh->is_persistent);
  return 0;
}

static int32_t pdo_tidb_serverless_stmt_fetch(pdo_stmt_t *stmt, enum pdo_fetch_orientation ori, zend_long offset)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;

  CHECK_PRECONDITION(handle->last_result, handle, ERR_NO_RESULT_SET, 0);

  if (++handle->current_row == handle->last_result->rows_count) {
    return 0;
  }
  return 1;
}

static int32_t pdo_tidb_serverless_stmt_describe(pdo_stmt_t *stmt, int32_t colno)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;
  struct pdo_column_data *cols = stmt->columns;
  int32_t i;

  CHECK_PRECONDITION(handle->last_result, handle, ERR_NO_RESULT_SET, 0);
  CHECK_PRECONDITION(colno < handle->last_result->columns_count, handle, ERR_INVALID_PARAMETER_NO, 0);
  if (cols[0].name) {
    return 1;
  }

  for (i = 0; i < handle->last_result->columns_count; i++) {
    cols[i].name = zend_string_init(handle->last_result->columns[i].name, strlen(handle->last_result->columns[i].name), 0);
    cols[i].precision = 0;
    cols[i].maxlen = 0;
  }
  return 1;
}

static int32_t pdo_tidb_serverless_stmt_get_col(
  pdo_stmt_t *stmt, int32_t colno, zval *result, enum pdo_param_type *type)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;

  CHECK_PRECONDITION(handle->last_result, handle, ERR_NO_RESULT_SET, 0);
  CHECK_PRECONDITION(colno < handle->last_result->columns_count, handle, ERR_INVALID_PARAMETER_NO, 0);
  CHECK_PRECONDITION(handle->current_row < handle->last_result->rows_count, handle, ERR_INVALID_PARAMETER_NO, 0);

  if (handle->last_result->rows[handle->current_row][colno]) {
    ZVAL_STRINGL_FAST(result, handle->last_result->rows[handle->current_row][colno], strlen(handle->last_result->rows[handle->current_row][colno]));
  }
  return 1;
}

static int32_t pdo_tidb_serverless_stmt_col_meta(pdo_stmt_t *stmt, zend_long colno, zval *return_value)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;
  const pdo_tidb_serverless_column *column;
  zval flags;
  size_t idx;

  CHECK_PRECONDITION(handle->last_result, handle, ERR_NO_RESULT_SET, FAILURE);
  CHECK_PRECONDITION(colno < handle->last_result->columns_count, handle, ERR_INVALID_PARAMETER_NO, FAILURE);

  array_init(return_value);
  array_init(&flags);
  column = handle->last_result->columns + colno;
  if (!column->nullable) {
    add_next_index_string(&flags, "not_null");
  }
  add_assoc_string(return_value, "native_type", column->type);

  enum pdo_param_type param_type = PDO_PARAM_STR;
  for (idx = 0; idx < sizeof(INTEGER_TYPES)/sizeof(INTEGER_TYPES[0]); ++idx) {
    if (strcmp(INTEGER_TYPES[idx], column->type) == 0) {
      param_type = PDO_PARAM_INT;
      break;
    }
  }
  add_assoc_long(return_value, "pdo_type", param_type);
  add_assoc_zval(return_value, "flags", &flags);

  zval_ptr_dtor(&flags);

  return SUCCESS;
}

static int32_t pdo_tidb_serverless_stmt_cursor_closer(pdo_stmt_t *stmt)
{
  pdo_tidb_serverless_stmt *handle = (pdo_tidb_serverless_stmt *)stmt->driver_data;

  pdo_tidb_serverless_free_result(&handle->last_result, stmt->dbh->is_persistent);
  handle->current_row = -1;
  return 1;
}

const struct pdo_stmt_methods tidb_serverless_stmt_methods = {
  pdo_tidb_serverless_stmt_dtor,
  pdo_tidb_serverless_stmt_execute,
  pdo_tidb_serverless_stmt_fetch,
  pdo_tidb_serverless_stmt_describe,
  pdo_tidb_serverless_stmt_get_col,
  NULL, /* param_hook */
  NULL, /* set_attr */
  NULL, /* get_attr */
  pdo_tidb_serverless_stmt_col_meta,
  pdo_tidb_serverless_stmt_next_rowset,
  pdo_tidb_serverless_stmt_cursor_closer
};
