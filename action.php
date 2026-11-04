<?php

/**
 * DokuWiki Plugin oauthindie (Action Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author  Tassoman <tassoman@gmail.com>
 */

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthindie\Indie;
use OAuth\Common\Exception\Exception as OAuthException;

/** IndieAuth login provider adapter for the DokuWiki OAuth plugin. */
class action_plugin_oauthindie extends Adapter
{
    /** Register the IndieAuth OAuth2 service implementation. */
    public function registerServiceClass()
    {
        return Indie::class;
    }

    /** IndieAuth providers do not have a preconfigured client secret. */
    public function getKey()
    {
        return rtrim(DOKU_URL, '/') . '/';
    }

    /** IndieAuth public clients use their site URL as client_id. */
    public function getSecret()
    {
        return '';
    }

    /**
     * Render an identity URL field and submit button in DokuWiki's OAuth login form.
     * The OAuth plugin's normal oauthlogin route handles the POST and starts this adapter.
     */
    public function loginButton()
    {
        global $ID;
        $action = wl($ID, ['oauthlogin' => $this->getServiceID()], false, '&');
        $label = hsc($this->getLabel());
        $placeholder = hsc($this->getLang('identityplaceholder'));
        $identityLabel = hsc($this->getLang('identitylabel'));
        $submit = hsc($this->getLang('loginbutton'));

        return '<form method="post" action="' . hsc($action) . '" class="plugin_oauthindie_login">' .
            '<label for="oauthindie-me">' . $identityLabel . '</label> ' .
            '<input id="oauthindie-me" type="url" name="me" required autocomplete="url" ' .
                'placeholder="' . $placeholder . '" aria-label="' . $identityLabel . '" /> ' .
            '<button type="submit" style="background-color:' . hsc($this->getColor()) . '">' . $submit . '</button>' .
            '</form>';
    }

    /**
     * Resolve identity and endpoints, then start the standard IndieAuth code flow.
     * Called by the OAuth plugin after initializing the service object.
     */
    public function login()
    {
        global $INPUT;
        $helper = plugin_load('helper', 'oauthindie');
        $me = $helper->normalizeIdentity($INPUT->post->str('me', ''));
        $endpoints = $helper->discoverEndpoints($me);

        // The OAuth manager creates the service before calling this method. The service
        // reads these per-login endpoints from the DokuWiki session during URL creation
        // and again when the provider redirects back.
        $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] = [
            'me' => $me,
            'authorization_endpoint' => $endpoints['authorization_endpoint'],
            'token_endpoint' => $endpoints['token_endpoint'],
        ];

        $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $_SESSION[DOKU_COOKIE]['auth']['oauthindie']['code_verifier'] = $verifier;

        $oauth = $this->getOAuthService();
        $url = $oauth->getAuthorizationUri([
            'me' => $me,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);
        send_redirect((string)$url);
    }

    /** Exchange callback code with the IndieAuth token endpoint and validate its me value. */
    public function checkToken()
    {
        global $INPUT;
        if (!$INPUT->get->has('code')) return false;

        $data = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        if (empty($data['me']) || empty($data['code_verifier'])) {
            throw new OAuthException('IndieAuth login session has expired. Please try again.');
        }

        $ok = parent::checkToken();
        if (!$ok) return false;

        $token = $this->getOAuthService()->getStorage()->retrieveAccessToken($this->getOAuthService()->service());
        $params = $token->getExtraParams();
        if (empty($params['me']) || $this->canonicalIdentity($params['me']) !== $this->canonicalIdentity($data['me'])) {
            throw new OAuthException('IndieAuth token response did not confirm the requested identity.');
        }
        return true;
    }

    /** IndieAuth clients can request scopes configured by the administrator. */
    public function getScopes()
    {
        $scopes = trim((string)$this->getConf('scopes'));
        return $scopes === '' ? [] : preg_split('/\s+/', $scopes);
    }

    public function getLabel()
    {
        return $this->getConf('label') ?: 'IndieAuth';
    }

    public function getColor()
    {
        return $this->getConf('color') ?: '#333333';
    }

    /** Canonical URL comparison without changing path or query identity components. */
    private function canonicalIdentity($url)
    {
        $parts = parse_url((string)$url);
        if (!$parts || empty($parts['host'])) return '';
        $scheme = strtolower($parts['scheme'] ?? 'https');
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) && !in_array($parts['port'], [80, 443], true) ? ':' . $parts['port'] : '';
        return $scheme . '://' . $host . $port . ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
    }
}
