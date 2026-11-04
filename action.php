<?php
/**
 * Map a Misskey account returned by its IndieAuth provider to DokuWiki user data.
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

    /** Render an identity URL field and submit button in DokuWiki's OAuth login form. */
    public function loginButton()
    {
        global $ID;
        $action = wl($ID, ['oauthlogin' => $this->getServiceID()], false, '&');
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

    /** Discover the user's IndieAuth server and begin authorization. */
    public function login()
    {
        global $INPUT;
        $helper = plugin_load('helper', 'oauthindie');
        $me = $helper->normalizeIdentity($INPUT->post->str('me', ''));
        $endpoints = $helper->discoverEndpoints($me);

        $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] = [
            'me' => $me,
            'authorization_endpoint' => $endpoints['authorization_endpoint'],
            'token_endpoint' => $endpoints['token_endpoint'],
        ];

        $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $_SESSION[DOKU_COOKIE]['auth']['oauthindie']['code_verifier'] = $verifier;

        $url = $this->getOAuthService()->getAuthorizationUri([
            'me' => $me,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);
        send_redirect((string)$url);
    }

    /** Exchange callback code and ensure the provider returned the requested identity. */
    public function checkToken()
    {
        global $INPUT;
        if (!$INPUT->get->has('code')) return false;

        $login = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        if (empty($login['me']) || empty($login['code_verifier'])) {
            throw new OAuthException('IndieAuth login session has expired. Please try again.');
        }

        if (!parent::checkToken()) return false;
        $oauth = $this->getOAuthService();
        $token = $oauth->getStorage()->retrieveAccessToken($oauth->service());
        $params = $token->getExtraParams();
        if (empty($params['me']) || $this->canonicalIdentity($params['me']) !== $this->canonicalIdentity($login['me'])) {
            throw new OAuthException('IndieAuth token response did not confirm the requested identity.');
        }
        return true;
    }

    /**
     * Fetch the authenticated Misskey account using the access token.
     * Misskey exposes the current account at POST /api/i and returns `username`, `host`, and `name`.
     * The email is a stable federated login identifier, username@host; local accounts use the
     * instance hostname from the discovered token endpoint when the API host field is null.
     */
    public function getUser()
    {
        $oauth = $this->getOAuthService();
        $login = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        $tokenEndpoint = $login['token_endpoint'] ?? '';
        $endpoint = $this->getConf('profileurl');
        if (!$endpoint) {
            $parts = parse_url($tokenEndpoint);
            if (!$parts || empty($parts['host'])) {
                throw new OAuthException('Cannot determine Misskey instance for profile lookup.');
            }
            $endpoint = 'https://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') . '/api/i';
        }

        try {
            $raw = $oauth->request($endpoint, 'POST', []);
        } catch (Exception $e) {
            throw new OAuthException('Failed to fetch authenticated account profile: ' . $e->getMessage());
        }
        $profile = json_decode($raw, true);
        if (!is_array($profile) || empty($profile['username'])) {
            throw new OAuthException('Misskey profile response is missing the username field.');
        }

        $username = trim((string)$profile['username']);
        $host = trim((string)($profile['host'] ?? ''));
        if ($host === '') {
            $host = (string)parse_url($endpoint, PHP_URL_HOST);
        }
        if ($host === '') throw new OAuthException('Cannot determine account hostname from Misskey profile.');

        $mail = $username . '@' . strtolower($host);
        $name = trim((string)($profile['name'] ?? ''));
        if ($name === '') $name = $username;
        $user = $username . '@' . strtolower($host);
        $grps = [];

        return compact('user', 'name', 'mail', 'grps');
    }

    public function getScopes()
    {
        $scopes = trim((string)$this->getConf('scopes'));
        return $scopes === '' ? ['read:account'] : preg_split('/\s+/', $scopes);
    }

    public function getLabel()
    {
        return $this->getConf('label') ?: 'IndieAuth';
    }

    public function getColor()
    {
        return $this->getConf('color') ?: '#333333';
    }

    /** Compare canonical identity URLs while preserving path and query. */
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
