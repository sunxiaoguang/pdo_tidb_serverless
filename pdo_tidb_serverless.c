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

#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(pdo_tidb_serverless)

ZEND_DECLARE_MODULE_GLOBALS(pdo_tidb_serverless)

PHP_INI_BEGIN()
PHP_INI_END()

static PHP_MINIT_FUNCTION(pdo_tidb_serverless)
{
  REGISTER_INI_ENTRIES();
  tidb_serverless_protocol_init();
  tidb_serverless_driver_init();
  return php_pdo_register_driver(&pdo_tidb_serverless_driver);
}

static PHP_MSHUTDOWN_FUNCTION(pdo_tidb_serverless)
{
  php_pdo_unregister_driver(&pdo_tidb_serverless_driver);
  tidb_serverless_driver_shutdown();
  tidb_serverless_protocol_shutdown();
  return SUCCESS;
}

static PHP_MINFO_FUNCTION(pdo_tidb_serverless)
{
  php_info_print_table_start();
  php_info_print_table_row(2, "PDO Driver for TiDB Serverless", "enabled");
  php_info_print_table_row(2, "Client version", PHP_PDO_TIDB_SERVERLESS_VERSION);
  php_info_print_table_end();
}

static PHP_RINIT_FUNCTION(pdo_tidb_serverless)
{
  return SUCCESS;
}

static PHP_RSHUTDOWN_FUNCTION(pdo_tidb_serverless)
{
  return SUCCESS;
}

static const zend_module_dep pdo_tidb_serverless_deps[] = {
  ZEND_MOD_REQUIRED("pdo")
  ZEND_MOD_REQUIRED("json")
  ZEND_MOD_REQUIRED("curl")
ZEND_MOD_END};

zend_module_entry pdo_tidb_serverless_module_entry = {
  STANDARD_MODULE_HEADER_EX, NULL,
  pdo_tidb_serverless_deps,
  "pdo_tidb_serverless",
  NULL,
  PHP_MINIT(pdo_tidb_serverless),
  PHP_MSHUTDOWN(pdo_tidb_serverless),
  PHP_RINIT(pdo_tidb_serverless),
  PHP_RSHUTDOWN(pdo_tidb_serverless),
  PHP_MINFO(pdo_tidb_serverless),
  PHP_PDO_TIDB_SERVERLESS_VERSION,
  PHP_MODULE_GLOBALS(pdo_tidb_serverless),
  NULL,
  NULL,
  NULL,
  STANDARD_MODULE_PROPERTIES_EX
};
