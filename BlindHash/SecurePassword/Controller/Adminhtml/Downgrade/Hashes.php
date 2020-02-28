<?php namespace BlindHash\SecurePassword\Controller\Adminhtml\Downgrade;

class Hashes extends \Magento\Backend\App\Action
{

    protected $resourceConfig;
    protected $downgrade;
    protected $hashes;

    public function __construct(
    \Magento\Backend\App\Action\Context $context, \BlindHash\SecurePassword\Model\Downgrade $downgrade, \Magento\Framework\App\Config\ConfigResource\ConfigInterface $resourceConfig, \BlindHash\SecurePassword\Model\Hashes $hashes)
    {
        parent::__construct($context);
        $this->resourceConfig = $resourceConfig;
        $this->downgrade = $downgrade;
        $this->hashes = $hashes;
    }

    public function execute()
    {
        if ($privateKey = $this->getRequest()->getParam('private_key')) {
            $count = $this->downgrade->downgradeAllPasswords($privateKey);
        } else {
            $this->getMessageManager()->addError(__('Please provide Unistall key to downgrade BlindHashes.'));
        }

        if ($count) {
            $this->getMessageManager()->addSuccess(__($count . ' password(s) has been downgraded from BlindHash.'));
            //Disable BlindHash
            $this->disableBlindHashProtection();
        } else {
            $this->getMessageManager()->addNotice(__('There are no BlindHash passwords.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }

    /**
     * Disable Blindhash Protection if there are now blindhashes left
     */
    private function disableBlindHashProtection()
    {
        $noOfBlindHashes = $this->hashes->getTotalBlindHashes();
        if ($noOfBlindHashes == 0) {
            $this->resourceConfig->saveConfig('blindhash/general/enabled', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
        }
    }
}
