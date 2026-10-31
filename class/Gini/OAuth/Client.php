<?php

namespace Gini\OAuth {

    class Client
    {
        private $_source;
        private $_token;

        private $_driver;
        private $_try_redirect = true;

        public function __construct($source)
        {
            $this->_source = $source;
            list($source_name,) = explode('/', $source);
            $this->_source_name = $source_name;

            $sessionKeyForToken =
                \Gini\Config::get('oauth.client')['session_key']['token'];
            if (isset($_SESSION[$sessionKeyForToken][$source])) {
                $data = $_SESSION[$sessionKeyForToken][$source];
                // \Gini\Logger::of('oauth')->error('invalid token: {error}!', ['error' => $token['error']]);
                if (!isset($data['error'])) {
                    $this->_token = new \League\OAuth2\Client\Token\AccessToken($data);
                }
            }

            $options = (array) \Gini\Config::get('oauth.client')['servers'][$source_name];
            $authUri = \Gini\Config::get('oauth.client')['auth_uri'] ?: 'oauth/client/auth';
            $driver_class = '\Gini\OAuth\Client\\' . ($options['driver'] ?: 'Unknown');

            $this->_driver = \Gini\IoC::construct($driver_class, [
                'clientId' => $options['client_id'],
                'clientSecret' => $options['client_secret'],
                'redirectUri' => URL($authUri, ['source' => $source]),
                'options' => $options
            ]);
        }

        public function authorize(
            array $options = [],
            ?callable $redirectHandler = null
        ) {
            $this->_driver->authorize($options, $redirectHandler);
        }

        public function tryRedirect($try_redirect = true)
        {
            $this->_try_redirect = !!$try_redirect;
            return $this;
        }

        public function getAccessToken($options = [])
        {
            if (!$this->_token && $this->_try_redirect) {
                $authUri = \Gini\Config::get('oauth.client')['auth_uri'] ?: 'oauth/client/auth';
                if (\Gini\CGI::route() != $authUri) {
                    $params = array_merge($options, [
                        'source' => $this->_source,
                        'redirect_uri' => URL('', $_GET)
                    ]);
                    \Gini\CGI::redirect($authUri, $params);
                }
            }
            if ($this->_token && $this->_token->hasExpired() && $this->_token->getRefreshToken()) {
                $params = array_merge($options, [
                    'refresh_token' => $this->_token->getRefreshToken()
                ]);
                $this->fetchAccessToken('refresh_token', $params);
            }
            return $this->_token;
        }

        public function fetchAccessToken($grant = 'authorization_code', $options = [])
        {
            $sessionKeyForToken =
                \Gini\Config::get('oauth.client')['session_key']['token'];
            try {
                $this->_token = $this->_driver->getAccessToken($grant, $options);
                $_SESSION[$sessionKeyForToken][$this->_source] = $this->_token->jsonSerialize();
            } catch (\Exception $e) {
                $this->_token = null;
                $_SESSION[$sessionKeyForToken][$this->_source] = [
                    'error' => $e->getMessage()
                ];
            }
        }

        public function getOwner()
        {
            $token = $this->getAccessToken();
            if ($token) {
                return $this->_driver->getResourceOwner($token)->toArray();
            }
        }

        // 为了向后兼容
        public function getUserDetails()
        {
            $data = $this->getOwner();
            return $data['type'] === 'user' ? [
                'username' => $data['id'],
            ] : [
                'username' => null
            ];
        }

        public function getUserName()
        {
            $token = $this->getAccessToken();
            if ($token) {
                $owner = $this->_driver->getResourceOwner($token);
                if ($owner['type'] !== 'user') return null;

                $username = $owner['id'];
                list($username, $backend) = \Gini\Auth::parseUserName($username);

                if ($backend) {
                    $backend .= '%' . $this->_source_name;
                } else {
                    $backend = $this->_source_name;
                }

                return \Gini\Auth::makeUserName($username, $backend);
            }
        }
    }
}
