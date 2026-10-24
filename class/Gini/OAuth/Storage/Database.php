<?php

namespace Gini\OAuth\Storage {

    // PHP 8.3: 移除 league/oauth2-server v3 Storage 接口依赖
    // 所有方法签名和实现保持不变，仅移除 implements 声明
    class Database
    {
        private $_db;

        public function __construct($name = null)
        {
            $this->_db = \Gini\Database::db($name);
        }

        public function getClient($clientId, $clientSecret = null, $redirectUri = null, $grantType = null)
        {
            $db = $this->_db;

            if ($clientSecret === null) {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oce.redirect_uri, oc.name, oc.auto_approve FROM _oauth_clients AS oc LEFT JOIN _oauth_client_endpoints AS oce ON oce.client_id = oc.id WHERE oc.id = :clientId AND oce.redirect_uri = :redirectUri',
                    null,
                    [':clientId' => $clientId, ':redirectUri' => $redirectUri]
                );
            } elseif ($redirectUri === null) {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oc.name, oc.auto_approve FROM _oauth_clients AS oc WHERE oc.id = :clientId AND oc.secret = :clientSecret',
                    null,
                    [':clientId' => $clientId, ':clientSecret' => $clientSecret]
                );
            } else {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oce.redirect_uri, oc.name, oc.auto_approve FROM _oauth_clients AS oc LEFT JOIN _oauth_client_endpoints AS oce ON oce.client_id = oc.id WHERE oc.id = :clientId AND oc.secret = :clientSecret AND oce.redirect_uri = :redirectUri',
                    null,
                    [':clientId' => $clientId, ':clientSecret' => $clientSecret, ':redirectUri' => $redirectUri]
                );
            }

            if ($st) {
                $row = $st->row(\PDO::FETCH_ASSOC);

                return $row ?: false;
            }

            return false;
        }

        public function createSession($clientId, $ownerType, $ownerId)
        {
            $db = $this->_db;
            $st = $db->query(
                'INSERT INTO _oauth_sessions (client_id, owner_type, owner_id, "group") VALUES (:clientId, :ownerType, :ownerId, :group)',
                null,
                [
                    ':clientId' => $clientId, ':group' => \Gini\Session::id(),
                    ':ownerType' => $ownerType, ':ownerId' => $ownerId,
                ]
            );

            return $st ? $db->lastInsertId() : false;
        }

        public function deleteSession($clientId, $ownerType, $ownerId)
        {
            $db = $this->_db;
            $db->query(
                'DELETE FROM "_oauth_sessions" WHERE "client_id"=:clientId AND "owner_type"=:ownerType AND "owner_id"=:ownerId AND "group"=:group',
                null,
                [
                    ':clientId' => $clientId, ':group' => \Gini\Session::id(),
                    ':ownerType' => $ownerType, ':ownerId' => $ownerId,
                ]
            );
        }

        public function getAllClients()
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT "client_id" FROM "_oauth_sessions" WHERE "group"=:group',
                null,
                [
                    ':group' => \Gini\Session::id(),
                ]
            );

            return ($st && $st->count() > 0) ? $st->rows(\PDO::FETCH_ASSOC) : [];
        }

        public function deleteAllSessions($clientId = null)
        {
            $db = $this->_db;
            if ($clientId) {
                $db->query(
                    'DELETE FROM "_oauth_sessions" WHERE "client_id"=:clientId AND "group"=:group',
                    null,
                    [
                        ':clientId' => $clientId, ':group' => \Gini\Session::id(),
                    ]
                );
            } else {
                $db->query(
                    'DELETE FROM "_oauth_sessions" WHERE "group"=:group',
                    null,
                    [
                        ':group' => \Gini\Session::id(),
                    ]
                );
            }
        }

        public function associateRedirectUri($sessionId, $redirectUri)
        {
            $db = $this->_db;
            $db->query(
                'INSERT INTO _oauth_session_redirects (session_id, redirect_uri) VALUES (:sessionId, :redirectUri)',
                null,
                [':sessionId' => $sessionId, ':redirectUri' => $redirectUri]
            );
        }

        public function associateAccessToken($sessionId, $accessToken, $expireTime)
        {
            $db = $this->_db;
            $st = $db->query(
                'INSERT INTO _oauth_session_access_tokens (session_id, access_token, access_token_expires) VALUES (:sessionId, :accessToken, :accessTokenExpire)',
                null,
                [':sessionId' => $sessionId, ':accessToken' => $accessToken, ':accessTokenExpire' => $expireTime]
            );

            return $st ? $db->lastInsertId() : false;
        }

        public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
        {
            $db = $this->_db;
            $db->query(
                'INSERT INTO _oauth_session_refresh_tokens (session_access_token_id, refresh_token, refresh_token_expires, client_id) VALUES (:accessTokenId, :refreshToken, :expireTime, :clientId)',
                null,
                [':accessTokenId' => $accessTokenId, ':refreshToken' => $refreshToken, ':expireTime' => $expireTime, ':clientId' => $clientId]
            );
        }

        public function associateAuthCode($sessionId, $authCode, $expireTime)
        {
            $db = $this->_db;
            $st = $db->query(
                'INSERT INTO _oauth_session_authcodes (session_id, auth_code, auth_code_expires) VALUES (:sessionId, :authCode, :authCodeExpires)',
                null,
                [':sessionId' => $sessionId, ':authCode' => $authCode, ':authCodeExpires' => $expireTime]
            );

            return $st ? $db->lastInsertId() : false;
        }

        public function removeAuthCode($sessionId)
        {
            $db = $this->_db;
            $db->query(
                'DELETE FROM _oauth_session_authcodes WHERE session_id = :sessionId',
                null,
                [':sessionId' => $sessionId]
            );
        }

        public function validateAuthCode($clientId, $redirectUri, $authCode)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT os.id AS session_id, osa.id AS authcode_id FROM _oauth_sessions AS os JOIN _oauth_session_authcodes AS osa ON osa.session_id = os.id JOIN _oauth_session_redirects AS osr ON osr.session_id = os.id WHERE os.client_id = :clientId AND osa.auth_code = :authCode AND osa.auth_code_expires >= UNIX_TIMESTAMP(NOW()) AND osr.redirect_uri = :redirectUri',
                null,
                [':clientId' => $clientId, ':redirectUri' => $redirectUri, ':authCode' => $authCode]
            );

            if ($st) {
                return $st->row(\PDO::FETCH_ASSOC);
            }

            return false;
        }

        public function validateAccessToken($accessToken)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT osat.session_id, os.client_id, os.owner_id, os.owner_type FROM _oauth_session_access_tokens AS osat JOIN _oauth_sessions AS os ON os.id = osat.session_id WHERE osat.access_token = :accessToken AND osat.access_token_expires >= UNIX_TIMESTAMP(NOW())',
                null,
                [':accessToken' => $accessToken]
            );

            if ($st) {
                return $st->row(\PDO::FETCH_ASSOC);
            }

            return false;
        }

        public function removeRefreshToken($refreshToken)
        {
            $db = $this->_db;
            $db->query(
                'DELETE FROM _oauth_session_refresh_tokens WHERE refresh_token = :refreshToken',
                null,
                [':refreshToken' => $refreshToken]
            );
        }

        public function validateRefreshToken($refreshToken, $clientId)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT session_access_token_id FROM _oauth_session_refresh_tokens WHERE refresh_token = :refreshToken AND refresh_token_expires >= UNIX_TIMESTAMP(NOW()) AND client_id = :clientId',
                null,
                [':refreshToken' => $refreshToken, ':clientId' => $clientId]
            );

            return ($st && $st->count() > 0) ? $st->value() : false;
        }

        public function setRefreshTokenExpireTime($refreshToken, $clientId, $expireTime)
        {
            $db = $this->_db;
            $st = $db->query(
                'UPDATE _oauth_session_refresh_tokens SET refresh_token_expires=:expireTime WHERE refresh_token = :refreshToken AND refresh_token_expires >= UNIX_TIMESTAMP(NOW()) AND client_id = :clientId',
                null,
                [':expireTime' => $expireTime, ':refreshToken' => $refreshToken, ':clientId' => $clientId]
            );
        }

        public function getAccessToken($accessTokenId)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT * FROM _oauth_session_access_tokens WHERE id = :accessTokenId',
                null,
                [':accessTokenId' => $accessTokenId]
            );

            if ($st) {
                return $st->row(\PDO::FETCH_ASSOC);
            }

            return false;
        }

        public function associateAuthCodeScope($authCodeId, $scopeId)
        {
            $db = $this->_db;
            $db->query(
                'INSERT INTO _oauth_session_authcode_scopes (oauth_session_authcode_id, scope_id) VALUES (:authCodeId, :scopeId)',
                null,
                [':authCodeId' => $authCodeId, ':scopeId' => $scopeId]
            );
        }

        public function getAuthCodeScopes($oauthSessionAuthCodeId)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT scope_id FROM _oauth_session_authcode_scopes WHERE oauth_session_authcode_id = :authCodeId',
                null,
                [':authCodeId' => $oauthSessionAuthCodeId]
            );

            return ($st && $st->count() > 0) ? $st->rows(\PDO::FETCH_ASSOC) : [];
        }

        public function associateScope($accessTokenId, $scopeId)
        {
            $db = $this->_db;
            $db->query(
                'INSERT INTO _oauth_session_token_scopes (session_access_token_id, scope_id) VALUE (:accessTokenId, :scopeId)',
                null,
                [':accessTokenId' => $accessTokenId, ':scopeId' => $scopeId]
            );
        }

        public function getScopes($accessToken)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT os.* FROM _oauth_session_token_scopes AS osts JOIN _oauth_session_access_tokens AS osat ON osat.id = osts.session_access_token_id JOIN _oauth_scopes AS os ON os.id = osts.scope_id WHERE osat.access_token = :accessToken',
                null,
                [':accessToken' => $accessToken]
            );

            return ($st && $st->count() > 0) ? $st->rows(\PDO::FETCH_ASSOC) : [];
        }

        public function getScope($scope, $clientId = null, $grantType = null)
        {
            $db = $this->_db;
            $st = $db->query(
                'SELECT * FROM _oauth_scopes WHERE scope = :scope',
                null,
                [':scope' => $scope]
            );

            return ($st && $st->count() > 0) ? $st->row(\PDO::FETCH_ASSOC) : false;
        }
    }
}
