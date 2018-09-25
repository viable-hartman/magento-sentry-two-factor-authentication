<?php
class HE_TwoFactorAuth_Model_Resource_Trusted_Collection extends Mage_Core_Model_Resource_Db_Collection_Abstract
{
    protected function _construct()
    {
        $this->_init('he_twofactorauth/trusted');
    }
}
