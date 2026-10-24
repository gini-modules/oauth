<?php

namespace Gini\OAuth {

    // PHP 8.3: 移除 league/oauth2-server v3 依赖，直接通过数据库验证 access token
    // 所有公开方法签名和返回格式保持不变
    class Resource
    {
        private $_isValid;
        private $_ownerType;
        private $_ownerId;
        private $_accessToken;
        private $_session;

        public function __construct($access_token)
        {
            $storageConfig = (array) \Gini\Config::get('oauth.server')['storage'];
            $sessionBackend = $storageConfig['session'] ?: $storageConfig['default'] ?: 'database';
            $this->_session = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $sessionBackend);

            try {
                $result = $this->_session->validateAccessToken($access_token);
                if ($result) {
                    $this->_isValid = true;
                    $this->_ownerType = $result['owner_type'];
                    $this->_ownerId = $result['owner_id'];
                    $this->_accessToken = $access_token;
                } else {
                    $this->_isValid = false;
                }
            } catch (\Exception $e) {
                $this->_isValid = false;
            }
        }

        public function isValid()
        {
            return $this->_isValid;
        }

        public function getUserName()
        {
            return $this->isValid() && $this->_ownerType == 'user' ? $this->_ownerId : false;
        }

        public function getOwnerType()
        {
            return $this->isValid() ? $this->_ownerType : false;
        }

        public function getOwnerId()
        {
            return $this->isValid() ? $this->_ownerId : false;
        }

        public function hasScope($scope)
        {
            if (!$this->isValid()) return false;
            $scopes = $this->_session->getScopes($this->_accessToken);
            foreach ($scopes as $s) {
                if ($s['scope'] === $scope) return true;
            }
            return false;
        }
    }
}
