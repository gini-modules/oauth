<?php

namespace Gini\OAuth {

    // PHP 8.3: 移除 league/oauth2-server v3 依赖，直接实现 OAuth2 授权码流程
    // 所有公开方法签名和返回格式保持不变
    class Authorization
    {
        private $_params;
        private $_session;
        private $_client;
        private $_scope;
        private $_accessTokenTTL = 3600;
        private $_refreshTokenTTL = 604800;

        public function __construct()
        {
            // ClientInterface $client, SessionInterface $session, ScopeInterface $scope
            $storageConfig = (array) \Gini\Config::get('oauth.server')['storage'];

            $sessionBackend = $storageConfig['session'] ?: $storageConfig['default'] ?: 'database';
            $this->_session = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $sessionBackend);

            $clientBackend = $storageConfig['client'] ?: $storageConfig['default'] ?: 'database';
            $this->_client = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $clientBackend);

            $scopeBackend = $storageConfig['scope'] ?: $storageConfig['default'] ?: 'database';
            $this->_scope = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $scopeBackend);
        }

        public function server()
        {
            // PHP 8.3: 原返回 League\OAuth2\Server\Authorization 实例，已移除该依赖
            return null;
        }

        public function isValid()
        {
            try {
                $clientId = $_GET['client_id'] ?? null;
                $redirectUri = $_GET['redirect_uri'] ?? null;
                $responseType = $_GET['response_type'] ?? null;

                if (!$clientId || !$redirectUri || $responseType !== 'code') {
                    return false;
                }

                $client = $this->_client->getClient($clientId, null, $redirectUri);
                if (!$client) {
                    return false;
                }

                // 验证 scope
                $scopeParam = $_GET['scope'] ?? '';
                $scopes = [];
                if ($scopeParam) {
                    $scopeList = explode(',', $scopeParam);
                    foreach ($scopeList as $scope) {
                        $scope = trim($scope);
                        if ($scope === '') continue;
                        $scopeDetails = $this->_scope->getScope($scope, $clientId, 'authorization_code');
                        if ($scopeDetails) {
                            $scopes[] = $scopeDetails;
                        }
                    }
                }

                $this->_params = [
                    'client_id' => $clientId,
                    'redirect_uri' => $redirectUri,
                    'response_type' => $responseType,
                    'state' => $_GET['state'] ?? '',
                    'scope' => $scopeParam,
                    'scopes' => $scopes,
                    'client_details' => $client,
                ];
            } catch (\Exception $e) {
                \Gini\Logger::of('oauth')->debug('checkAuthoriseParams: {error}!', ['error' => $e->getMessage()]);
                return false;
            }
            return true;
        }

        public function clientDetails()
        {
            return $this->_params['client_details'];
        }

        public function authorize($username, $scope = 'user')
        {
            $clientId = $this->_params['client_id'];
            $redirectUri = $this->_params['redirect_uri'];

            // 创建 session（$scope 此处实际为 owner_type，与 v3 行为一致）
            $sessionId = $this->_session->createSession($clientId, $scope, $username);
            $this->_session->associateRedirectUri($sessionId, $redirectUri);

            // 生成授权码
            $authCode = bin2hex(random_bytes(20));
            $authCodeExpires = time() + 600;
            $authCodeId = $this->_session->associateAuthCode($sessionId, $authCode, $authCodeExpires);

            // 关联 scope
            if (!empty($this->_params['scopes'])) {
                foreach ($this->_params['scopes'] as $scopeDetails) {
                    $this->_session->associateAuthCodeScope($authCodeId, $scopeDetails['id']);
                }
            }

            return $this->makeRedirectUri($redirectUri, [
                'code' => $authCode,
                'state' => isset($this->_params['state']) ? $this->_params['state'] : '',
            ]);
        }

        public function deny()
        {
            return $this->makeRedirectUri(
                $this->_params['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'error_message' => 'The resource owner or authorization server denied the request.',
                    'state' => isset($this->_params['state']) ? $this->_params['state'] : ''
                ]
            );
        }

        public function setRefreshTokenExpireTime($refresh_token, $client_id, $expireTime)
        {
            $this->_session->setRefreshTokenExpireTime($refresh_token, $client_id, $expireTime);
            return true;
        }

        public function issueAccessToken($params = null, $internal = false)
        {
            if (!is_array($params)) {
                $params = $_POST;
            }

            if (!empty($params['ttl'])) {
                $this->_accessTokenTTL = (int) $params['ttl'];
            }

            try {
                $grantType = $params['grant_type'] ?? '';

                if ($internal && $grantType === 'internal') {
                    return $this->_completeInternalGrant($params);
                }

                switch ($grantType) {
                    case 'authorization_code':
                        return $this->_completeAuthCodeGrant($params);
                    case 'refresh_token':
                        return $this->_completeRefreshTokenGrant($params);
                    default:
                        header('HTTP/1.1 400 Bad Request');
                        return [
                            'error' => 'unsupported_grant_type',
                            'error_description' => 'The authorization grant type is not supported.',
                        ];
                }
            } catch (\Exception $e) {
                return [
                    'error' => 'undefined_error',
                    'error_description' => $e->getMessage(),
                ];
            }
        }

        /**
         * authorization_code 授权码换 token
         */
        private function _completeAuthCodeGrant(array $params)
        {
            $clientId = $params['client_id'] ?? '';
            $clientSecret = $params['client_secret'] ?? '';
            $redirectUri = $params['redirect_uri'] ?? '';
            $authCode = $params['code'] ?? '';

            // 验证客户端
            $client = $this->_client->getClient($clientId, $clientSecret, $redirectUri);
            if (!$client) {
                header('HTTP/1.1 401 Unauthorized');
                return [
                    'error' => 'invalid_client',
                    'error_description' => 'Client authentication failed.',
                ];
            }

            // 验证授权码
            $authCodeData = $this->_session->validateAuthCode($clientId, $redirectUri, $authCode);
            if (!$authCodeData) {
                header('HTTP/1.1 400 Bad Request');
                return [
                    'error' => 'invalid_request',
                    'error_description' => 'The request includes an invalid authorization code.',
                ];
            }

            $sessionId = $authCodeData['session_id'];
            $authCodeId = $authCodeData['authcode_id'];

            // 删除已使用的授权码
            $this->_session->removeAuthCode($sessionId);

            // 生成 access token
            $accessToken = bin2hex(random_bytes(20));
            $accessTokenExpiresIn = $this->_accessTokenTTL;
            $accessTokenExpires = time() + $accessTokenExpiresIn;
            $accessTokenId = $this->_session->associateAccessToken($sessionId, $accessToken, $accessTokenExpires);

            // 迁移 auth code 的 scope 到 access token
            $scopes = $this->_session->getAuthCodeScopes($authCodeId);
            foreach ($scopes as $scope) {
                $this->_session->associateScope($accessTokenId, $scope['scope_id']);
            }

            $response = [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires' => $accessTokenExpires,
                'expires_in' => $accessTokenExpiresIn,
            ];

            // 生成 refresh token
            $refreshToken = bin2hex(random_bytes(20));
            $refreshTokenExpires = time() + $this->_refreshTokenTTL;
            $this->_session->associateRefreshToken($accessTokenId, $refreshToken, $refreshTokenExpires, $clientId);
            $response['refresh_token'] = $refreshToken;

            return $response;
        }

        /**
         * refresh_token 刷新 token
         */
        private function _completeRefreshTokenGrant(array $params)
        {
            $clientId = $params['client_id'] ?? '';
            $clientSecret = $params['client_secret'] ?? '';
            $refreshToken = $params['refresh_token'] ?? '';

            // 验证客户端
            $client = $this->_client->getClient($clientId, $clientSecret);
            if (!$client) {
                header('HTTP/1.1 401 Unauthorized');
                return [
                    'error' => 'invalid_client',
                    'error_description' => 'Client authentication failed.',
                ];
            }

            // 验证 refresh token
            $accessTokenId = $this->_session->validateRefreshToken($refreshToken, $clientId);
            if (!$accessTokenId) {
                header('HTTP/1.1 400 Bad Request');
                return [
                    'error' => 'invalid_request',
                    'error_description' => 'The refresh token is invalid or has expired.',
                ];
            }

            // 获取原 access token 的 session 和 scope
            $oldAccessToken = $this->_session->getAccessToken($accessTokenId);
            $sessionId = $oldAccessToken['session_id'];
            $oldScopes = $this->_session->getScopes($oldAccessToken['access_token']);

            // 删除旧 refresh token
            $this->_session->removeRefreshToken($refreshToken);

            // 生成新 access token
            $newAccessToken = bin2hex(random_bytes(20));
            $accessTokenExpiresIn = $this->_accessTokenTTL;
            $accessTokenExpires = time() + $accessTokenExpiresIn;
            $newAccessTokenId = $this->_session->associateAccessToken($sessionId, $newAccessToken, $accessTokenExpires);

            // 迁移 scope
            foreach ($oldScopes as $scope) {
                $this->_session->associateScope($newAccessTokenId, $scope['id']);
            }

            $response = [
                'access_token' => $newAccessToken,
                'token_type' => 'Bearer',
                'expires' => $accessTokenExpires,
                'expires_in' => $accessTokenExpiresIn,
            ];

            // 生成新 refresh token
            $newRefreshToken = bin2hex(random_bytes(20));
            $refreshTokenExpires = time() + $this->_refreshTokenTTL;
            $this->_session->associateRefreshToken($newAccessTokenId, $newRefreshToken, $refreshTokenExpires, $clientId);
            $response['refresh_token'] = $newRefreshToken;

            return $response;
        }

        /**
         * internal 内部授权（机器对机器，无用户交互）
         */
        private function _completeInternalGrant(array $params)
        {
            $clientId = $params['client_id'] ?? '';
            $ownerType = $params['owner_type'] ?? 'user';
            $ownerId = $params['owner_id'] ?? '';
            $scopeParam = $params['scope'] ?? '';

            // 创建 session
            $sessionId = $this->_session->createSession($clientId, $ownerType, $ownerId);

            // 生成 access token
            $accessToken = bin2hex(random_bytes(20));
            $accessTokenExpiresIn = $this->_accessTokenTTL;
            $accessTokenExpires = time() + $accessTokenExpiresIn;
            $accessTokenId = $this->_session->associateAccessToken($sessionId, $accessToken, $accessTokenExpires);

            // 关联 scope
            if ($scopeParam) {
                $scopes = explode(',', $scopeParam);
                foreach ($scopes as $scope) {
                    $scope = trim($scope);
                    if ($scope === '') continue;
                    $scopeDetails = $this->_scope->getScope($scope, $clientId, 'internal');
                    if ($scopeDetails) {
                        $this->_session->associateScope($accessTokenId, $scopeDetails['id']);
                    }
                }
            }

            $response = [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires' => $accessTokenExpires,
                'expires_in' => $accessTokenExpiresIn,
            ];

            // 生成 refresh token
            $refreshToken = bin2hex(random_bytes(20));
            $refreshTokenExpires = time() + $this->_refreshTokenTTL;
            $this->_session->associateRefreshToken($accessTokenId, $refreshToken, $refreshTokenExpires, $clientId);
            $response['refresh_token'] = $refreshToken;

            return $response;
        }

        public function destroyCurrentSessions()
        {
            $this->_session->deleteAllSessions();
        }

        public function getCurrentSessions()
        {
            return $this->_session->getAllClients();
        }

        /**
         * 构建 redirect URI（替代 League\OAuth2\Server\Util\RedirectUri::make）
         */
        private function makeRedirectUri($uri, array $params)
        {
            $separator = (strpos($uri, '?') !== false) ? '&' : '?';
            return $uri . $separator . http_build_query($params);
        }
    }
}
