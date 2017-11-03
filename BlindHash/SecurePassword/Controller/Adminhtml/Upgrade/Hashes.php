<?php namespace BlindHash\SecurePassword\Controller\Adminhtml\Upgrade;

class Hashes extends \Magento\Backend\App\Action
{

    protected $scopeConfig;
    protected $upgrade;
    protected $messageManager;

    public function __construct(
    \Magento\Backend\App\Action\Context $context, \BlindHash\SecurePassword\Model\Upgrade $upgrade, \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Message\ManagerInterface $messageManager)
    {
        parent::__construct($context);
        $this->scopeConfig = $scopeConfig;
        $this->upgrade = $upgrade;
        $this->messageManager = $messageManager;
    }

    public function execute()
    {
        if (!(boolean) $this->scopeConfig->getValue('blindhash/general/enabled')) {
            $this->messageManager->addNotice(__('Please enable Blind hash Hashing before upgrade.'));
            $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
            return;
        }
        $count = $this->upgrade->upgradeAllPasswords();

        if ($count) {
            $this->messageManager->addSuccess(__($count . ' password(s) has been upgraded to blind hash.'));
        } else {
            $this->messageManager->addNotice(__('There are no old hash passwords left.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
