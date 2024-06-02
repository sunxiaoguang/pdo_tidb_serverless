PHP_ARG_WITH([pdo-tidb-serverless],
  [Enable TiDB Serverless support for PDO],
  [AS_HELP_STRING([--enable-pdo-tidb-serverless],
    [Enable TiDB Serverless PDO support])],
  [yes])

if test "$PHP_PDO_TIDB_SERVERLESS" != "no"; then
  if test "$PHP_PDO" = "no" && test "$ext_shared" = "no"; then
    AC_MSG_ERROR([PDO is not enabled! Add --enable-pdo to your configure line.])
  fi

  PHP_CHECK_LIBRARY(utf8proc, utf8proc_iterate, , [
    AC_MSG_ERROR(pdo_tidb_serverless module requires libutf8proc)
  ], [])

  PHP_ADD_LIBRARY(utf8proc, 1, PDO_TIDB_SERVERLESS_SHARED_LIBADD)

  PHP_CHECK_PDO_INCLUDES

  PHP_NEW_EXTENSION(pdo_tidb_serverless, pdo_tidb_serverless.c tidb_serverless_driver.c tidb_serverless_statement.c tidb_serverless_protocol.c, $ext_shared,,-I$pdo_cv_inc_path -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 -Wall -Werror)
  PHP_SUBST(PDO_TIDB_SERVERLESS_SHARED_LIBADD)

  PHP_ADD_EXTENSION_DEP(pdo_tidb_serverless, pdo)
  PDO_TIDB_SERVERLESS_MODULE_TYPE=external
  PHP_SUBST_OLD(PDO_TIDB_SERVERLESS_MODULE_TYPE)
fi
