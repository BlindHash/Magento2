<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Upgrade;

class Button extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Return Upgrade button html
     *
     * @param  AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        $url = $this->getUrl("blindhash/upgrade/hashes");
        $button = $this->getLayout()->createBlock(
                'Magento\Backend\Block\Widget\Button'
            )->setData(
            [
                'id' => 'upgrade_hashes',
                'label' => __('Upgrade Hashes!'),
                'onclick' => __("setLocation('$url')"),
            ]
        );

        return $button->toHtml();
    }
}
