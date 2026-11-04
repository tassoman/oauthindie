<?php
/**
 * DokuWiki Plugin oauthindie (Action Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author Tassoman <tassoman@gmail.com>
 */

use dokuwiki\Extension\Event;
use dokuwiki\Extension\EventHandler;
use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthindie\Indie;
use OAuth\Common\Exception\Exception as OAuthException;

class action_plugin_oauthindie extends Adapter
{
    public function register(EventHandler $controller)
    {
        parent::register($controller);
        $controller->register_hook('TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'handleMetaHeader');
    }

    /** Add the configured OAuth callback URI as an IndieAuth redirect_uri link. */
    public function handleMetaHeader(Event &$event, $param)
    {
        /** @var helper_plugin_oauth $oauthHelper */
        $oauthHelper = plugin_load('helper', 'oauth');
        if (!$oauthHelper) return;
        $redirectUri = $oauthHelper->redirectURI();

        if (!isset($event->data['link']) || !is_array($event->data['link'])) $event->data['link'] = [];
        foreach ($event->data['link'] as $link) {
            if (($link['rel'] ?? '') === 'redirect_uri' && ($link['href'] ?? '') === $redirectUri) return;
        }
        $event->data['link'][] = ['rel' => 'redirect_uri', 'href' => $redirectUri];
    }

    public function registerServiceClass()
    {
        return Indie::class;
    }

    /** IndieAuth client ID is the canonical DokuWiki URL. */
    public function getKey()
    {
        return rtrim(DOKU_URL, '/') . '/';
    }

    public function getSecret()
    {
        return '';
    }

    /** Render identity controls inside the OAuth plugin's existing login form. */
    public function loginButton()
    {
        return '<div class="plugin_oauthindie_login">' .
            '<label for="oauthindie-me">' . hsc($this->getLang('identitylabel')) . '</label> ' .
            '<input id="oauthindie-me" type="text" name="me" required autocomplete="url" ' .
                'placeholder="' . hsc($this->getLang('identityplaceholder')) . '" ' .
                'pattern="[A-Za-z0-9.-]+(:[0-9]+)?(/[^ ]*)?" ' .
                'title="' . hsc($this->getLang('identityinvalid')) . '" /> ' .
            '<button type="submit" name="oauthlogin" value="' . hsc($this->getServiceID()) . '" ' .
                'style="background-color:' . hsc($this->getColor()) . '">' .
                hsc($this->getLang('loginbutton')) . '</button></div>';
    }

    /** Begin IndieAuth discovery and authorization. */
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
            'issuer' => $endpoints['issuer'],
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

    /** Exchange callback code and validate RFC 9207 issuer when supplied. */
    public function checkToken()
    {
        global $INPUT;
        if (!$INPUT->get->has('code')) return false;

        $login = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        if (empty($login['me']) || empty($login['code_verifier'])) {
            throw new OAuthException('IndieAuth login session has expired. Please try again.');
        }

        $callbackIssuer = $INPUT->get->str('iss', '');
        if ($callbackIssuer !== '') {
            $expectedIssuer = $login['issuer'] ?: $this->issuerFromEndpoint($login['authorization_endpoint'] ?? '');
            if (!$expectedIssuer || $this->canonicalIssuer($callbackIssuer) !== $this->canonicalIssuer($expectedIssuer)) {
                throw new OAuthException('IndieAuth authorization response issuer did not match the discovered server.');
            }
        }

        // Misskey's token response has access_token, token_type and scope but does not
        // include IndieAuth's optional `me` property. The callback issuer plus successful
        // PKCE token exchange is the applicable server validation for Misskey.
        return parent::checkToken();
    }

    /** Extract current Misskey account and map it to DokuWiki user fields. */
    public function getUser()
    {
        $oauth = $this->getOAuthService();
        $login = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        $endpoint = $this->getConf('profileurl');
        if (!$endpoint) {
            $parts = parse_url($login['token_endpoint'] ?? '');
            if (!$parts || empty($parts['host'])) throw new OAuthException('Cannot determine Misskey instance for profile lookup.');
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
        if ($host === '') $host = (string)parse_url($endpoint, PHP_URL_HOST);
        if ($host === '') throw new OAuthException('Cannot determine account hostname from Misskey profile.');

        $user = $username . '@' . strtolower($host);
        $mail = $user; // Synthetic federated identifier; not a deliverable email address.
        $name = trim((string)($profile['name'] ?? '')) ?: $username;
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

    /** Normalize issuer URL for RFC 9207 comparison. */
    private function canonicalIssuer($issuer)
    {
        $parts = parse_url((string)$issuer);
        if (!$parts || empty($parts['host'])) return '';
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) && !in_array($parts['port'], [80, 443], true) ? ':' . $parts['port'] : '';
        $path = rtrim($parts['path'] ?? '', '/');
        return $scheme . '://' . $host . $port . $path;
    }

    private function issuerFromEndpoint($endpoint)
    {
        $parts = parse_url((string)$endpoint);
        if (!$parts || empty($parts['host'])) return '';
        return ($parts['scheme'] ?? 'https') . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
