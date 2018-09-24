<?php

/** @var Mage_Core_Model_Resource_Setup $this */
$this->startSetup();
$connection = $this->getConnection();

$tableName = $this->getTable('he_twofactorauth/trusted');

$table = $connection->newTable($tableName);
$table->addColumn('trusted_id', Varien_Db_Ddl_Table::TYPE_INTEGER, 10, [
    'unsigned' => true,
    'nullable' => false,
    'primary' => true,
    'identity' => true,
], 'Trusted Device ID');
$table->addColumn('date_time', Varien_Db_Ddl_Table::TYPE_TIMESTAMP, null, [
    'nullable' => false,
    'default' => '0000-00-00 00:00:00',
], 'Creation time');
$table->addColumn('user_id', Varien_Db_Ddl_Table::TYPE_INTEGER, 10, [
    'unsigned' => true,
    'nullable' => false,
], 'Admin user ID');
$table->addColumn('device_name', Varien_Db_Ddl_Table::TYPE_TEXT, 255, [
    'nullable' => false,
], 'Device Name');
$table->addColumn('token', Varien_Db_Ddl_Table::TYPE_TEXT, 255, [
    'nullable' => false,
], 'Token');
$table->addColumn('ip', Varien_Db_Ddl_Table::TYPE_TEXT, 39, [
    'nullable' => false,
], 'Device IP address');

$adminUserTableName = $this->getTable('admin/user');
$userIdFkName = $this->getFkName(
    $adminUserTableName, 'user_id',
    $tableName, 'user_id'
);
$table->addForeignKey(
    $userIdFkName, 'user_id',
    $adminUserTableName, 'user_id',
    Varien_Db_Ddl_Table::ACTION_CASCADE,
    Varien_Db_Ddl_Table::ACTION_CASCADE
);

$uniqueName = $this->getIdxName($tableName, ['user_id', 'device_name', 'ip']);
$table->addIndex($uniqueName, ['user_id', 'device_name', 'ip'], [
    'type' => Varien_Db_Adapter_Interface::INDEX_TYPE_UNIQUE,
]);

$table->setComment('2FA Trusted Device');

$connection->createTable($table);

$this->endSetup();
