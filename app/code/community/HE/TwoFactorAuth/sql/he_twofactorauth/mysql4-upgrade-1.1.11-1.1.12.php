<?php
// create the  table on admin_user

$installer = $this;
$installer->startSetup();
$installer->getConnection()
    ->addColumn($installer->getTable('admin/user'),
    'twofactor_disable',
    array(
        'type' => Varien_Db_Ddl_Table::TYPE_BOOLEAN,
        'length' => 1,
        'default' => null,
        'comment' => 'Disable TwoFactor'
    )
);
$installer->endSetup();
