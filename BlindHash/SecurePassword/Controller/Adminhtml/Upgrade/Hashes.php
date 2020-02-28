<?php namespace BlindHash\SecurePassword\Controller\Adminhtml\Upgrade;

class Hashes extends \Magento\Backend\App\Action
{

    protected $scopeConfig;
    protected $upgrade;

    public function __construct(
    \Magento\Backend\App\Action\Context $context, \BlindHash\SecurePassword\Model\Upgrade $upgrade, \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig)
    {
        parent::__construct($context);
        $this->scopeConfig = $scopeConfig;
        $this->upgrade = $upgrade;
    }

    public function execute()
    {
        if (!(boolean) $this->scopeConfig->getValue('blindhash/general/enabled')) {
            $this->getMessageManager()->addNotice(__('Please enable BlindHash hashing before upgrade.'));
            $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
            return;
        }
        $count = $this->upgrade->upgradeAllPasswords();

        if ($count) {
            $this->getMessageManager()->addSuccess(__($count . ' password(s) has been upgraded to BlindHash.'));
        } else {
            $this->getMessageManager()->addNotice(__('There are no legacy hashed passwords to upgrade.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
