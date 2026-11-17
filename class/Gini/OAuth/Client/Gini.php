<?php

namespace Gini\OAuth\Client;

use \League\OAuth2\Client\Provider\AbstractProvider;
use \League\OAuth2\Client\Token\AccessToken;
use \League\OAuth2\Client\Provider\ResourceOwnerInterface;
use \League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use \Psr\Http\Message\ResponseInterface;

class GiniOwner implements ResourceOwnerInterface, \ArrayAccess
{
    /**
     * @var array
     */
    protected $response;

    public function __construct(array $response)
    {
        if (array_key_exists('username', $response)) {
            $this->response = [
                'type' => 'user',
                'id' => $response['username']
            ];
        } else {
            $this->response = $response;
        }
    }

    /**
     * Returns the identifi
     * er of the authorized resource owner.
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->response['id'];
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->response[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->response[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->response[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->response[$offset]);
    }
}


class Gini extends AbstractProvider
{
    protected $options;

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return URL($this->options['auth']);
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return URL($this->options['token'], $params);
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return URL(($this->options['owner'] ?? null) ?: $this->options['user'], ['access_token' => (string) $token]);
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['user'];
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GiniOwner($response);
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data[$this->responseError])) {
            $error = $data[$this->responseError];
            if (!is_string($error)) {
                $error = var_export($error, true);
            }
            $code  = $this->responseCode && !empty($data[$this->responseCode]) ? $data[$this->responseCode] : 0;
            if (!is_int($code)) {
                $code = intval($code);
            }
            throw new IdentityProviderException($error, $code, $data);
        }
    }
}
