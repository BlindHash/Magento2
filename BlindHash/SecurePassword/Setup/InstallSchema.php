<?php
namespace BlindHash\SecurePassword\Setup;

use Magento\Framework\Setup\InstallSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;
use Magento\Framework\DB\Ddl\Table;
use Magento\Framework\DB\Adapter\AdapterInterface;

class InstallSchema implements InstallSchemaInterface
{

    public function install(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $setup->startSetup();
        
        // Customer's password column varchar to text
        $setup->getConnection()
            ->changeColumn($setup->getTable('customer_entity'), 'password_hash', 'password_hash', ['type' => Table::TYPE_TEXT, 'nullable' => true, 'default' => '']);
        
        // Admin's password column varchar to text
        $setup->getConnection()->changeColumn($setup->getTable('admin_user'), 'password', 'password', ['type' => Table::TYPE_TEXT, 'nullable' => true, 'default' => '']);

        $setup->endSetup();
    }
}
