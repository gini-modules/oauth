<?php

namespace Gini\Controller\CGI\OAuth;

class Client extends \Gini\Controller\CGI
{
    public function actionAuth()
    {
        $form = $this->form();

        $source = $form['source'];
        $client = \Gini\IoC::construct('\Gini\OAuth\Client', $source);

        $sessionKeyForToken =
            \Gini\Config::get('oauth.client')['session_key']['token'];
        $sessionKeyForRedirectUri =
            \Gini\Config::get('oauth.client')['session_key']['redirect_uri'];

        if (isset($form['error'])) {
            $_SESSION[$sessionKeyForToken][$source] = '@' . $form['error'];
        } elseif (isset($form['code'])) {
            // got authorization code, try to acquire access token
            $client->fetchAccessToken('authorization_code', ['code' => $form['code']]);
        } else {
            // start oauth process...
            $_SESSION[$sessionKeyForRedirectUri][$source] = $form['redirect_uri'] ?: '/';
            $client->authorize();
            return;
        }

        // redirect to original place
        $redirect_uri = $_SESSION[$sessionKeyForRedirectUri][$source];
        unset($_SESSION[$sessionKeyForRedirectUri][$source]);
        $this->redirect($redirect_uri);
    }
}
