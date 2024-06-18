--TEST--
Test transaction support
--EXTENSIONS--
pdo_tidb_serverless
--SKIPIF--
<?php
require_once 'tidb_serverless_pdo_test.inc';
TiDBServerlessPDOTest::skip();
?>
--FILE--
<?php
require_once 'tidb_serverless_pdo_test.inc';
$db = TiDBServerlessPDOTest::factory();

TiDBServerlessPDOTest::createTestTable($db);
if ($db->getAttribute(PDO::ATTR_AUTOCOMMIT) !== 1) {
    printf("1: autocommit is expected by default\n");
}

if (!$db->beginTransaction()) {
    printf("2: Cannot start a transaction, [%s] [%s]\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->getAttribute(PDO::ATTR_AUTOCOMMIT) !== 1) {
    printf("3: autocommit is expected after beginTransaction()\n");
}

if ($db->exec('DELETE FROM test') == 0) {
    printf("3: Didn't delete rows as expected\n");
}

$db = null;
$db = TiDBServerlessPDOTest::factory();
$db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, true);

if (!($stmt = $db->query('SELECT id, label FROM test ORDER BY id ASC'))) {
    printf("4: Failed to query. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

$row = $stmt->fetch(PDO::FETCH_ASSOC);
var_dump($row);

if (!$db->beginTransaction()) {
    printf("5: Failed to begin transaction. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->exec(sprintf('DELETE FROM test WHERE id = %d', $row['id'])) !== 1)
    printf("6: Delete didn't affected 1 row as expected. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));

if (!$db->commit()) {
    printf("7: Failed to commit. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->getAttribute(PDO::ATTR_AUTOCOMMIT) !== 1) {
    printf("8: autocommit is expected after commit()\n");
}

if (!($stmt = $db->query(sprintf('SELECT id, label FROM test WHERE id = %d', $row['id'])))) {
    printf("9: Failed to query. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

var_dump($stmt->fetch(PDO::FETCH_ASSOC));

if (!$db->beginTransaction()) {
    printf("10: Failed to begin transaction. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->exec(sprintf("INSERT INTO test(id, label) VALUES (%d, 'z')", $row['id'])) !== 1) {
    printf("10: Insert didn't affect 1 row as expected. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if (!($stmt = $db->query(sprintf('SELECT id, label FROM test WHERE id = %d', $row['id'])))) {
    printf("11: Failed to query. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

$new_row1 = $stmt->fetch(PDO::FETCH_ASSOC);
var_dump($new_row1);

if (!$db->commit()) {
    printf("12: Failed to commit. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if (!($stmt = $db->query(sprintf('SELECT id, label FROM test WHERE id = %d', $row['id'])))) {
    printf("13: Failed to query. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

$new_row2 = $stmt->fetch(PDO::FETCH_ASSOC);
if ($new_row1 != $new_row2) {
    printf("14: Resultsets are different!\n");
    var_dump($new_row1);
    var_dump($new_row2);
}

if (!$db->beginTransaction()) {
    printf("15: Failed to begin transaction [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->exec(sprintf('DELETE FROM test WHERE id = %d', $row['id'])) !== 1) {
    printf("16: Delete didn't affect 1 row. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if (!$db->rollback()) {
    printf("17: Failed to rollback. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

if ($db->getAttribute(PDO::ATTR_AUTOCOMMIT) !== 1) {
    printf("18: autocommit is expected after rollback\n");
}

if (!($stmt = $db->query(sprintf('SELECT id, label FROM test WHERE id = %d', $row['id'])))) {
    printf("19: Failed to query. [%s] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

$new_row2 = $stmt->fetch(PDO::FETCH_ASSOC);
if ($new_row1 != $new_row2) {
    printf("20: Resultsets are different!\n");
    var_dump($new_row1);
    var_dump($new_row2);
}

if (!$db->beginTransaction()) {
    printf("21: Failed to begin transaction, [%d] %s\n", $db->errorCode(), implode(' ', $db->errorInfo()));
}

try {
    if ($db->beginTransaction()) {
        printf("22: Nested transaction did not fail as expected.\n");
    }
} catch (PDOException $e) {
    assert($e->getMessage() != '');
}

print "done!";
?>
--CLEAN--
<?php
require_once 'tidb_serverless_pdo_test.inc';
TiDBServerlessPDOTest::dropTestTable();
?>
--EXPECT--
array(2) {
  ["id"]=>
  string(1) "1"
  ["label"]=>
  string(1) "a"
}
bool(false)
array(2) {
  ["id"]=>
  string(1) "1"
  ["label"]=>
  string(1) "z"
}
done!
