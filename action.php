<?php
/**
 * IndieAuth provider adapter for the DokuWiki OAuth plugin.
 *
 * Keep the adapter focused on DokuWiki form integration and converting provider
 * profile data to the user structure expected by the OAuth plugin. The Indie.php
 * service owns protocol-specific endpoint and token behavior.
 */

use dokuwiki\Extension\Event;
use dokuwiki\Extension\EventHandler;
use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthindie\Indie;
use OAuth\Common\Exception\Exception as OAuthException;

class action_plugin_oauthindie extends Adapter
{
    /**
     * Register this service with OAuth and advertise the configured callback URL
     * to IndieAuth clients such as Misskey.
     *
     * @inheritDoc
     */
    public function register(EventHandler $controller)
    {
        parent::register($controller);
        $controller->register_hook('TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'handleMetaHeader');
    }

    /** Add the OAuth plugin's actual redirect URI as a discovery link in <head>. */
    public function handleMetaHeader(Event &$event, $param)
    {
        /** @var helper_plugin_oauth $oauthHelper */
        $oauthHelper = plugin_load('helper', 'oauth');
        if (!$oauthHelper) return;

        $redirectUri = $oauthHelper->redirectURI();
        if (!isset($event->data['link']) || !is_array($event->data['link'])) {
            $event->data['link'] = [];
        }

        // Avoid duplicate redirect_uri links if another component already added it.
        foreach ($event->data['link'] as $link) {
            if (($link['rel'] ?? '') === 'redirect_uri' && ($link['href'] ?? '') === $redirectUri) {
                return;
            }
        }

        $event->data['link'][] = [
            'rel' => 'redirect_uri',
            'href' => $redirectUri,
        ];
    }

    /** @inheritDoc */
    public function registerServiceClass()
    {
        return Indie::class;
    }

    /**
     * IndieAuth's client_id is the DokuWiki site's canonical URL. An empty key
     * prevents the OAuth plugin from hiding this dynamically configured service.
     *
     * @return string
     */
    public function getKey()
    {
        return rtrim(DOKU_URL, '/') . '/';
    }

    /** @inheritDoc */
    public function getSecret()
    {
        return '';
    }

    /**
     * The OAuth plugin places service controls inside its own login form. Render
     * just the fields and submit button here; a nested form is invalid HTML and
     * browsers can discard its controls. Posting the service name starts the
     * OAuth plugin's normal login flow while preserving the submitted identity.
     *
     * @return string
     */
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
                hsc($this->getLang('loginbutton')) .
            '</button></div>';
    }

    /** Start discovery and authorization after the OAuth plugin's login form submits. */
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

    /** Exchange callback code and verify that the provider authenticated this identity. */
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
     * Fetch the authenticated Misskey account and map it to DokuWiki user fields.
     *
     * @return array{user:string,name:string,mail:string,grps:array}
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
        if ($host === '') $host = (string)parse_url($endpoint, PHP_URL_HOST);
        if ($host === '') throw new OAuthException('Cannot determine account hostname from Misskey profile.');

        $user = $username . '@' . strtolower($host);
        $mail = $user; // Misskey does not provide a deliverable email; this is the fediverse login identifier.
        $name = trim((string)($profile['name'] ?? '')) ?: $username;
        $grps = [];
        return compact('user', 'name', 'mail', 'grps');
    }

    /** @inheritDoc */
    public function getScopes()
    {
        $scopes = trim((string)$this->getConf('scopes'));
        return $scopes === '' ? ['read:account'] : preg_split('/\s+/', $scopes);
    }

    /** @inheritDoc */
    public function getLabel()
    {
        return $this->getConf('label') ?: 'IndieAuth';
    }

    /** @inheritDoc */
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
