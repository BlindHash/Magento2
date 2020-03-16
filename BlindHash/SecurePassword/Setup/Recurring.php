<?php
namespace BlindHash\SecurePassword\Setup;

use Magento\Framework\Setup\InstallSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;
use Magento\Framework\DB\Ddl\Table;
use Magento\Framework\DB\Adapter\AdapterInterface;
use Psr\Log\LoggerInterface;

class Recurring implements InstallSchemaInterface
{
	protected $logger;

	/**
	 * InstallData constructor.
	 * @param LoggerInterface $logger
	 */
	public function __construct(LoggerInterface $logger)
	{
	    $this->logger = $logger;
	}
    
    /**
     * Change password type from varchar to text
     * 
     * @param SchemaSetupInterface $setup
     * @param ModuleContextInterface $context
     */
    public function install(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $setup->startSetup();
        
        // Customer's password column varchar to text
	$this->logger->info('Modifying customer_entity.password_hash column schema data type to be TEXT...');
        $setup->getConnection()->changeColumn($setup->getTable('customer_entity'), 'password_hash', 'password_hash', ['type' => Table::TYPE_TEXT, 'nullable' => true, 'default' => '']);
        
        // Admin's password column varchar to text
	$this->logger->info('Modifying admin_user.password column schema data type to be TEXT...');
        $setup->getConnection()->changeColumn($setup->getTable('admin_user'), 'password', 'password', ['type' => Table::TYPE_TEXT, 'nullable' => true, 'default' => '']);

        $setup->endSetup();
    }
}
