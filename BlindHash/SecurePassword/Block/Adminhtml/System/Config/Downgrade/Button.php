<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Downgrade;

class Button extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Downgrade hash button along with needful js
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {

        $url = $this->getUrl("blindhash/downgrade/hashes");
        $downgradeHashesJs = " <script type='text/javascript'>
            function downgradeHashes(){
            
                var privateKey = document.getElementById('blindhash_general_api_private_key'); 
                if(privateKey.style.display == 'none'){
                    privateKey.style.display = 'block';
                }  
                
                if(privateKey.value)
                    setLocation('{$url}?private_key='+privateKey.value);
                else
                    alert('Please provide private key in below input to downgrade hashes');
                }</script>";
        $button = $this->getLayout()->createBlock(
                'Magento\Backend\Block\Widget\Button'
            )->setData(
            [
                'id' => 'downgrade_hashes',
                'label' => __('Downgrade Hashes!'),
                'onclick' => __("downgradeHashes()"),
            ]
        );

        return $button->toHtml() . $downgradeHashesJs;
    }
}
