<?php namespace BlindHash\SecurePassword\Helper;

use \Magento\Framework\App\Helper\AbstractHelper;

class Data extends AbstractHelper
{

    protected $scopeConfig;
    protected $resourceConfig;

    public function __construct(
    \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\App\Config\ConfigResource\ConfigInterface $resourceConfig)
    {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Update Request Counters
     * @param array $counterArray
     */
    public function updatedBlindHashRequestCounters($counterArray)
    {
        if (!(boolean) $this->scopeConfig->getValue('blindhash/general/enabled')) {
            return;
        }

        $defaultScope = \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT;
        $defaultStoreId = \Magento\Store\Model\Store::DEFAULT_STORE_ID;


        $this->resourceConfig->saveConfig('blindhash/request/total_error_count', $counterArray->total_error_count + (int) $this->scopeConfig->getValue('blindhash/request/total_error_count'), $defaultScope, $defaultStoreId);
        $this->resourceConfig->saveConfig('blindhash/request/total_request_count', $counterArray->total_request_count + (int) $this->scopeConfig->getValue('blindhash/request/total_request_count'), $defaultScope, $defaultStoreId);
        $this->resourceConfig->saveConfig('blindhash/request/total_retry_count', $counterArray->total_retry_count + (int) $this->scopeConfig->getValue('blindhash/request/total_retry_count'), $defaultScope, $defaultStoreId);
    }
}
