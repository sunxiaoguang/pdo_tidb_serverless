# TiDB Serverless PDO Connector

Welcome to the TiDB Serverless PDO Connector. This connector is designed to facilitate the use of the PHP Data Objects (PDO) extension with TiDB Serverless, a cloud-native, distributed SQL database compatible with MySQL protocols. The connector implements the serverless driver protocol over HTTPs, enabling seamless integration with PHP applications.

## Overview

The TiDB Serverless PDO Connector allows PHP developers to interact with TiDB Serverless using the familiar PDO interface. It supports the serverless driver protocol, which is optimized for serverless environments and provides a lightweight and efficient way to manage database connections.

## Features

- **Serverless Driver Protocol**: Implements the serverless driver protocol over HTTPs for efficient database operations in a serverless context.
- **PDO Compatibility**: Provides a standard PDO interface for database operations, making it easy to integrate with existing PHP applications.
- **Security**: Ensures secure communication with the TiDB Serverless database using encrypted TLS connections.

## Requirements

- PHP 8.3 or newer
- PDO extension enabled in PHP
- TiDB Serverless instance with access credentials

## Installation

To install the TiDB Serverless PDO Connector, you can build and install with the following commands:

```bash
phpize
configure
make install
```

## Configuration

Before using the connector, you need to create a PDO object with your TiDB Serverless credentials and connection details:

```php
<?php

$user = "username";
$pass = "password";

// Establish a connection to the TiDB Serverless database
try {
    $pdo = new PDO('tidb_serverless:host=gateway01.us-west-2.prod.aws.tidbcloud.com;dbname=test', $user, $pass);
    echo "Connection established successfully.";
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}
```

## Usage

Once configured, you can use the PDO connector just like any other PDO instance:

```php
<?php
// Perform database operations using the PDO interface
try {
    $stmt = $pdo->prepare("SELECT * FROM your_table");
    $stmt->execute();
    $results = $stmt->fetchAll();
    print_r($results);
} catch (PDOException $e) {
    echo "Error executing query: " . $e->getMessage();
}
```

## Contributing

Contributions to the TiDB Serverless PDO Connector are welcome! Please follow the standard GitHub workflow:

1. Fork the repository.
2. Create a new branch for your changes.
3. Make your changes and ensure tests pass.
4. Submit a pull request.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Disclaimer

This is an early version of the TiDB Serverless PDO Connector and may contain bugs or incomplete features. Use it with caution and report any issues you encounter.

---

Enjoy developing with TiDB Serverless and PHP! If you have any questions or need further assistance, feel free to reach out to the community or the maintainers.
