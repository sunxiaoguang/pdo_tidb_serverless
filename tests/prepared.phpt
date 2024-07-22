--TEST--
Test prepared statements
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

function test_prepared($case_id, $query, $params = []) {
    try {
        $db = TiDBServerlessPDOTest::factory();
        $db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, true);
        $stmt = $db->prepare($query);
        $ret = $stmt->execute($params);
        if (str_starts_with($query, 'SELECT')) {
            var_dump($stmt->fetchAll(PDO::FETCH_ASSOC));
        }
        $db = null;
    } catch (PDOException $e) {
        printf("[%3d] %s, [%s] %s\n", $case_id, $e->getMessage(), $e->errorCode(), implode(' ', $db->errorInfo()));
    }
}

$case_id = 0;
test_prepared($case_id++, "SELECT 1 AS `one`");
test_prepared($case_id++, "DROP TABLE IF EXISTS test");
test_prepared($case_id++, "CREATE TABLE test(id INT, label CHAR(255)) ENGINE=InnoDB");
test_prepared($case_id++, "INSERT INTO test(id, label) VALUES(1, ':placeholder')");
test_prepared($case_id++, "SELECT label FROM test");
test_prepared($case_id++, "DELETE FROM test");
test_prepared($case_id++, "INSERT INTO test(id, label) VALUES(1, ':placeholder')", [':placeholder' => 'first row']);
test_prepared($case_id++, "SELECT label FROM test");
test_prepared($case_id++, "DELETE FROM test");
test_prepared($case_id++, "INSERT INTO test(id, label) VALUES(1, :placeholder)", [':placeholder' => 'first row']);
test_prepared($case_id++, "INSERT INTO test(id, label) VALUES(2, :placeholder)", [':placeholder' => 'second row']);
test_prepared($case_id++, "SELECT label FROM test");
test_prepared($case_id++, "SELECT label FROM test WHERE :placeholder > 1", [':placeholder' => 'id']);
test_prepared($case_id++, "SELECT :placeholder FROM test WHERE id > 1", [':placeholder' => 'id']);
test_prepared($case_id++, "SELECT :placeholder FROM test WHERE :placeholder > :placeholder", [':placeholder' => 'test']);

print "done!";
?>
--CLEAN--
<?php
require_once 'tidb_serverless_pdo_test.inc';
?>
--EXPECTF--
array(1) {
  [0]=>
  array(1) {
    ["one"]=>
    string(1) "1"
  }
}
array(1) {
  [0]=>
  array(1) {
    ["label"]=>
    string(12) ":placeholder"
  }
}

Warning: PDOStatement::execute(): SQLSTATE[HY093]: Invalid parameter number: number of bound variables does not match number of tokens in %s on line %d
array(0) {
}
array(2) {
  [0]=>
  array(1) {
    ["label"]=>
    string(9) "first row"
  }
  [1]=>
  array(1) {
    ["label"]=>
    string(10) "second row"
  }
}
array(0) {
}
array(1) {
  [0]=>
  array(1) {
    ["id"]=>
    string(2) "id"
  }
}
array(0) {
}
done!

