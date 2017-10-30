<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Total;

class BlindHashes extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Return total blindhashes count
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return int
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        // TODO return total blindhashes
        return "No of BlindHashes";
    }
}
