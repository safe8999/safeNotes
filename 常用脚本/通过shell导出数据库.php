<?php
ini_set('memory_limit', '2200M');
try {
    // 数据库连接配置
    $host = "127.0.0.1";
    $port = "3306";  // 端口号
    $user = "root";
    $password = "mm123123";
    $database = "product";

     // 设置最大执行时间为0，表示没有时间限制
    set_time_limit(0);

    // 设置数据库连接的超时时间
    $options = array(
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 30000  // 设置数据库连接超时为300秒（5分钟）
    );

    // 连接数据库，包含端口号
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$database", $user, $password, $options);

    $stmt = $pdo->query("SHOW TABLES");
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $filename = date('YmdHis'). '.sql';
    $fileHandle = fopen($filename, 'w');

    foreach ($tables as $table) {
        $query = "SELECT * FROM $table";
        $result = $pdo->query($query);

        while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
            $fields = array_keys($row);
            $values = array_values($row);

            $insert_sql = "INSERT INTO $table (";
            $insert_sql .= implode(', ', $fields) . ") VALUES (";
            foreach ($values as $value) {
                $value = $pdo->quote($value);
                $insert_sql .= $value . ", ";
            }
            $insert_sql = rtrim($insert_sql, ', ') . ");\n";

            fwrite($fileHandle, $insert_sql);
        }
    }

    fclose($fileHandle);
    echo "备份文件已生成：$filename";

} catch (PDOException $e) {
    echo "错误: " . $e->getMessage();
}