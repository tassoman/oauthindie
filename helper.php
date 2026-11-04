<?php
/**
 * DokuWiki Plugin oauthindie (Helper Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author Tassoman <tassoman@gmail.com>
 */

use dokuwiki\HTTP\DokuHTTPClient;

class helper_plugin_oauthindie extends \dokuwiki\Extension\Plugin
{
    /**
     * Normalize a submitted hostname or identity URL into an HTTPS URL.
     * A bare Misskey hostname such as misskey.example is accepted.
     *
     * @param string $identity
     * @return string
     * @throws InvalidArgumentException
     */
    public function normalizeIdentity($identity)
    {
        $identity = trim((string)$identity);
        if ($identity === '') {
            throw new InvalidArgumentException($this->getLang('identityrequired'));
        }
        if (!preg_match('~^https?://~i', $identity)) {
            $identity = 'https://' . $identity;
        }
        if (filter_var($identity, FILTER_VALIDATE_URL) === false) {
            throw new InvalidArgumentException($this->getLang('identityinvalid'));
        }

        $parts = parse_url($identity);
        if (!$parts || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException($this->getLang('identityinvalid'));
        }
        if (!in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)) {
            throw new InvalidArgumentException($this->getLang('identityinvalid'));
        }

        $host = strtolower(trim($parts['host'], '[]'));
        if (!filter_var($host, FILTER_VALIDATE_IP) &&
            !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            throw new InvalidArgumentException($this->getLang('identityinvalid'));
        }
        $this->assertPublicHost($host);
        return $identity;
    }

    /**
     * Discover Misskey OAuth endpoints using RFC 8414 metadata at the instance origin.
     * If no usable metadata document is published, fall back to IndieAuth rel links at
     * the submitted identity URL.
     *
     * @param string $identity
     * @return array{authorization_endpoint:string,token_endpoint:string}
     * @throws RuntimeException
     */
    public function discoverEndpoints($identity)
    {
        $identity = $this->normalizeIdentity($identity);
        $parts = parse_url($identity);
        $origin = strtolower($parts['scheme']) . '://' . $parts['host'] .
            (isset($parts['port']) ? ':' . $parts['port'] : '');

        // Misskey profile pages need not include endpoint rel links. Misskey publishes
        // OAuth authorization server metadata for the whole instance at this URL.
        $metadataResponse = $this->fetchUrl($origin . '/.well-known/oauth-authorization-server', 'application/json');
        if ($metadataResponse !== false) {
            $metadata = json_decode($metadataResponse['body'], true);
            if (is_array($metadata) && !empty($metadata['authorization_endpoint']) && !empty($metadata['token_endpoint'])) {
                return [
                    'authorization_endpoint' => $this->validateEndpoint($metadata['authorization_endpoint']),
                    'token_endpoint' => $this->validateEndpoint($metadata['token_endpoint']),
                ];
            }
        }

        // Standard IndieAuth discovery from a user's identity page.
        $page = $this->fetchUrl($identity, 'text/html, application/xhtml+xml;q=0.9, */*;q=0.1');
        if ($page !== false) {
            $found = ['authorization_endpoint' => null, 'token_endpoint' => null];
            foreach ((array)$page['headers'] as $name => $values) {
                if (strtolower($name) !== 'link') continue;
                foreach ((array)$values as $header) {
                    foreach ($this->parseLinkHeader($header) as $link) {
                        $this->recordEndpoint($found, $link['rel'], $link['href'], $identity);
                    }
                }
            }

            if (class_exists(DOMDocument::class)) {
                $document = new DOMDocument();
                $previous = libxml_use_internal_errors(true);
                $document->loadHTML('<?xml encoding="utf-8" ?>' . (string)$page['body'], LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
                libxml_clear_errors();
                libxml_use_internal_errors($previous);

                foreach ($document->getElementsByTagName('link') as $element) {
                    $href = trim($element->getAttribute('href'));
                    $rels = preg_split('/\s+/', strtolower(trim($element->getAttribute('rel'))));
                    foreach ($rels as $rel) {
                        $this->recordEndpoint($found, $rel, $href, $identity);
                    }
                }
            }

            if (!empty($found['authorization_endpoint']) && !empty($found['token_endpoint'])) {
                return $found;
            }
        }

        throw new RuntimeException($this->getLang('noauthorizationendpoint'));
    }

    /** Fetch a public HTTPS URL with redirects disabled. */
    private function fetchUrl($url, $accept)
    {
        $parts = parse_url($url);
        if (!$parts || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) return false;
        $this->assertPublicHost(strtolower(trim($parts['host'], '[]')));

        $http = new DokuHTTPClient();
        $http->timeout = 10;
        $http->max_redirect = 0;
        $http->headers['Accept'] = $accept;
        if (!$http->sendRequest($url, '', 'GET') || $http->status < 200 || $http->status >= 300) {
            return false;
        }
        return ['body' => (string)$http->resp_body, 'headers' => (array)$http->resp_headers];
    }

    /** Validate a discovered authorization or token endpoint. */
    private function validateEndpoint($url)
    {
        if (!is_string($url) || trim($url) === '') {
            throw new RuntimeException($this->getLang('endpointmustbehttps'));
        }
        $parts = parse_url($url);
        if (!$parts || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
            throw new RuntimeException($this->getLang('endpointmustbehttps'));
        }
        $this->assertPublicHost(strtolower(trim($parts['host'], '[]')));
        return $url;
    }

    /** Validate and store a discovered endpoint from a Link header or HTML link element. */
    private function recordEndpoint(array &$found, $rel, $href, $base)
    {
        $rel = strtolower($rel);
        if (!in_array($rel, ['authorization_endpoint', 'token_endpoint'], true) || $href === '') return;
        $found[$rel] = $this->validateEndpoint($this->resolveUrl($base, $href));
    }

    /** Resolve an endpoint reference against the identity URL. */
    private function resolveUrl($base, $reference)
    {
        if (preg_match('~^https://~i', $reference)) return $reference;
        if (strpos($reference, '//') === 0) return 'https:' . $reference;
        $parts = parse_url($base);
        $origin = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        if (strpos($reference, '/') === 0) return $origin . $reference;
        return $origin . rtrim(dirname($parts['path'] ?? '/'), '/') . '/' . $reference;
    }

    /** Parse Link header entries, including multiple rel values on a link. */
    private function parseLinkHeader($header)
    {
        $links = [];
        if (!preg_match_all('/<([^>]+)>\s*((?:;[^,]*)*)/', (string)$header, $matches, PREG_SET_ORDER)) return $links;
        foreach ($matches as $match) {
            if (!preg_match('/(?:^|;)\s*rel\s*=\s*"?([^";]+)"?/i', $match[2], $relMatch)) continue;
            foreach (preg_split('/\s+/', trim($relMatch[1])) as $rel) {
                $links[] = ['href' => trim($match[1]), 'rel' => $rel];
            }
        }
        return $links;
    }

    /** Reject loopback, private, reserved, and unresolved hostnames. */
    private function assertPublicHost($host)
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $addresses = [$host];
        } else {
            $addresses = gethostbynamel($host) ?: [];
            if (function_exists('dns_get_record')) {
                foreach ((array)@dns_get_record($host, DNS_AAAA) as $record) {
                    if (!empty($record['ipv6'])) $addresses[] = $record['ipv6'];
                }
            }
        }
        if (!$addresses) throw new RuntimeException($this->getLang('identityinvalid'));
        foreach (array_unique($addresses) as $address) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new RuntimeException($this->getLang('privatehost'));
            }
        }
    }
}
