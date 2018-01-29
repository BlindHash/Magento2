<?php namespace BlindHash\SecurePassword\Model\System\Config\Source;

class Legacy implements \Magento\Framework\Option\ArrayInterface
{

    public function toOptionArray()
    {
        return [
            ['value' => '0', 'label' => __('Unencrypted')],
            ['value' => '1', 'label' => __('Encrypted')],
        ];
    }

    public function toArray()
    {
        return [0 => __('Unencrypted'), 1 => __('Encrypted')];
    }
}
