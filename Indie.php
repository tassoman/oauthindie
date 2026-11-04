<?php

/**
 * DokuWiki Plugin oauthindie (Indie Service Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author  Tassoman <tassoman@gmail.com>
 */

namespace dokuwiki\plugin\oauthindie;

use dokuwiki\plugin\oauth\Service\AbstractOAuth2Base;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\OAuth2\Token\StdOAuth2Token;

/** OAuth2 service implementation with per-login IndieAuth endpoint discovery and PKCE. */
class Indie extends AbstractOAuth2Base
{
    public function needsStateParameterInAuthUrl()
    {
        return true;
    }

    public function getAuthorizationEndpoint()
    {
        $endpoint = $this->loginData('authorization_endpoint');
        if (!$endpoint) throw new \RuntimeException('No IndieAuth authorization endpoint was discovered.');
        return new Uri($endpoint);
    }

    public function getAccessTokenEndpoint()
    {
        $endpoint = $this->loginData('token_endpoint');
        if (!$endpoint) throw new \RuntimeException('No IndieAuth token endpoint was discovered.');
        return new Uri($endpoint);
    }

    protected function getAuthorizationMethod()
    {
        return self::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /** Use IndieAuth's user-entered identity as the authorization request's me parameter. */
    public function getAuthorizationUri(array $additionalParameters = [])
    {
        $data = $this->loginData();
        if (empty($data['me'])) throw new \RuntimeException('No IndieAuth identity was entered.');
        $additionalParameters['me'] = $data['me'];
        return parent::getAuthorizationUri($additionalParameters);
    }

    /**
     * IndieAuth token endpoints may return JSON or form-urlencoded data and PKCE requires
     * adding the verifier to the standard OAuth authorization-code token request.
     */
    public function requestAccessToken($code, $state = null)
    {
        if ($state !== null) $this->validateAuthorizationState($state);
        $data = $this->loginData();
        if (empty($data['code_verifier'])) throw new TokenResponseException('Missing PKCE verifier for IndieAuth token exchange.');

        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->credentials->getConsumerId(),
            'redirect_uri' => $this->credentials->getCallbackUrl(),
            'code_verifier' => $data['code_verifier'],
        ];
        $response = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $body,
            $this->getExtraOAuthHeaders()
        );
        $token = $this->parseAccessTokenResponse($response);
        $this->storage->storeAccessToken($this->service(), $token);
        return $token;
    }

    /** Parse the JSON and URL-encoded response formats used by IndieAuth servers. */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);
        if (!is_array($data)) {
            parse_str($responseBody, $data);
        }
        if (!is_array($data) || isset($data['error']) || empty($data['access_token'])) {
            $error = is_array($data) ? ($data['error_description'] ?? $data['error'] ?? '') : '';
            throw new TokenResponseException('Unable to parse IndieAuth token response. ' . $error);
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        unset($data['access_token']);
        if (isset($data['expires_in'])) {
            $token->setLifeTime((int)$data['expires_in']);
            unset($data['expires_in']);
        } else {
            $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        }
        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }
        $token->setExtraParams($data);
        return $token;
    }

    /** Read this login's dynamic values from the DokuWiki auth session. */
    private function loginData($key = null)
    {
        $data = $_SESSION[DOKU_COOKIE]['auth']['oauthindie'] ?? [];
        return $key === null ? $data : ($data[$key] ?? null);
    }
}
