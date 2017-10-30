<?php namespace BlindHash\SecurePassword\Model\Observer;

class AdminUserAuthenticated implements \Magento\Framework\Event\ObserverInterface
{

    protected $scopeConfig;
    protected $encryptor;

    public function __construct(\Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Encryption\EncryptorInterface $encryptor)
    {
        $this->scopeConfig = $scopeConfig;
        $this->encryptor = $encryptor;
    }

    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        if (!$this->scopeConfig->getValue('blindhash/general/enabled')) {
            return;
        }

        $password = $observer->getPassword();
        $user = $observer->getUser();

        if (!$this->encryptor->IsBlindHashed($user->getPassword())
        ) {
            $user->setPassword($password);
            $user->save();
        }
    }
}
