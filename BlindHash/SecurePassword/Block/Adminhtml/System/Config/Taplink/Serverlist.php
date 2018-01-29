<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Taplink;

use Magento\Framework\Data\Form\Element\AbstractElement;

class Serverlist extends \Magento\Config\Block\System\Config\Form\Field
{

    protected function _getElementHtml(AbstractElement $element)
    {
        $element->setDisabled('disabled');
        return $element->getElementHtml();
    }
}
