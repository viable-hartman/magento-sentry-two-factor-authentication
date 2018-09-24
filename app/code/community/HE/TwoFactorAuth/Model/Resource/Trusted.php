<?php
class HE_TwoFactorAuth_Model_Resource_Trusted extends Mage_Core_Model_Resource_Db_Abstract
{
    private $trustedHelper;
    protected function _construct()
    {
        $this->_init('he_twofactorauth/trusted', 'trusted_id');
        $this->trustedHelper = Mage::helper("he_twofactorauth/trusted");
    }

    public function addActivity($userId)
    {
        $token = $this->trustedHelper->getToken();
        $ipAddress = $this->trustedHelper->getIpAddress();
        $userAgent = $this->trustedHelper->getUserAgent();
        $row = $this->getRowFromActivity($userId, $token, $ipAddress, $userAgent);
        $result = $this->saveActivity(array($row));
        if ($result) {
            $this->addTokenCookie($token);
        }
    }

    protected function getRowFromActivity($userId, $token, $ipAddress, $userAgent)
    {
        $now = Mage::getSingleton('core/date')->gmtDate();
        return [
            'date_time' => $now,
            'user_id' => $userId,
            'device_name' => $userAgent,
            'token' => $token,
            'ip' => $ipAddress,
        ];
    }

    protected function saveActivity($rows)
    {
        $adapter = $this->_getWriteAdapter();

        $updates = [
           'token' => 'token',
           'date_time' => 'date_time',
        ];

        $result = $adapter->insertOnDuplicate($this->getMainTable(), $rows, $updates);
        return $result;
    }

    protected function addTokenCookie($token)
    {
        $cookie = Mage::getSingleton('core/cookie');
        $cookie->set('he_tfa_trusted', $token ,31536000,'/');
    }

    public function findActivity()
    {
        $user = Mage::getSingleton('admin/session')->getUser();
        $userId = $user->getId();
        $ipAddress = $this->trustedHelper->getIpAddress();
        $userAgent = $this->trustedHelper->getUserAgent();
        $cookieToken = Mage::getModel("core/cookie")->get("he_tfa_trusted");
        $tfaCollection = Mage::getModel("he_twofactorauth/trusted")->getCollection()
            ->addFieldToFilter("device_name", array("eq" => $userAgent))
            ->addFieldToFilter("ip", array("eq" => $ipAddress))
            ->addFieldToFilter("user_id", array("eq" => $user->getId()))
            ->addFieldToFilter("token", array("eq" => $cookieToken));
        if ($tfaCollection->count() == 1) {
            $this->addActivity($userId);
            return true;
        }
        return false;
    }
}
