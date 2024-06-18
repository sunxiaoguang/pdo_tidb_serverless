<?php

if (getenv('PDO_TIDB_SERVERLESS_TEST_HOST') === false) {
    throw new Exception("Missing required environment variable PDO_TIDB_SERVERLESS_TEST_DSN");
}

class TiDBServerlessPDOTest {
    // create an instance of the PDO driver, based on
    // the current environment
    static function factory() {
        $host = getenv('PDO_TIDB_SERVERLESS_TEST_HOST');
        $user = getenv('PDO_TIDB_SERVERLESS_TEST_USER');
        $pass = getenv('PDO_TIDB_SERVERLESS_TEST_PASS');
        $attr = getenv('PDO_TIDB_SERVERLESS_TEST_ATTR');
        if (is_string($attr) && strlen($attr)) {
            $attr = unserialize($attr);
        } else {
            $attr = NULL;
        }

        if ($user === false) $user = NULL;
        if ($pass === false) $pass = NULL;

        $dsn = "tidb_serverless:host=$host;dbname=test";
        $db = new PDO($dsn, $user, $pass, $attr);

        if (!$db) {
            die("Could not create PDO object (DSN=$dsn, user=$user)\n");
        }
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
        $db->setAttribute(PDO::ATTR_CASE, PDO::CASE_LOWER);
        $db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, true);
        return $db;
    }

    static function skip() {
        try {
            $db = TiDBServerlessPDOTest::factory();
        } catch (PDOException $e) {
            die("skip " . $e->getMessage());
        }
    }

    static function dropTestTable($db = NULL) {
        if (is_null($db))
            $db = self::factory();

        $db->exec('DROP TABLE IF EXISTS test');
    }

    static function createTestTable($db, $engine = null) {
        $db->exec('DROP TABLE IF EXISTS test');
        $db->exec('CREATE TABLE test(id INT, label CHAR(1), PRIMARY KEY(id)) ENGINE=InnoDB');
        $db->exec("INSERT INTO test(id, label) VALUES (1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e'), (6, 'f')");
    }
}

?>
