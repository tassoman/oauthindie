<?php
/**
 * DokuWiki Plugin oauthindie (Helper Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author  Tassoman <tassoman@gmail.com>
 */

use dokuwiki\HTTP\DokuHTTPClient;

class helper_plugin_oauthindie extends \dokuwiki\Extension\Plugin
{
    /**
     * Normalize a user-entered identity URL and require an HTTP(S) hostname.
     * IndieAuth discovery is performed server-side, so local/private hosts are rejected.
     *
     * @param string $identity
     * @return string
     * @throws InvalidArgumentException
     */
    public function normalizeIdentity($identity)
    {
        $identity = trim($identity);
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
        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
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
     * Discover IndieAuth endpoints from HTML links or HTTP Link headers.
     * Redirects are deliberately not followed to avoid turning discovery into an SSRF proxy.
     *
     * @param string $identity
     * @return array{authorization_endpoint:string, token_endpoint:string|null}
     * @throws RuntimeException
     */
    public function discoverEndpoints($identity)
    {
        $identity = $this->normalizeIdentity($identity);
        $http = new DokuHTTPClient();
        $http->timeout = 10;
        $http->max_redirect = 0;
        $http->headers['Accept'] = 'text/html, application/xhtml+xml;q=0.9, */*;q=0.1';

        if (!$http->sendRequest($identity, '', 'GET') || $http->status < 200 || $http->status >= 300) {
            throw new RuntimeException(sprintf($this->getLang('discoveryfailed'), $http->status));
        }

        $found = ['authorization_endpoint' => null, 'token_endpoint' => null];
        foreach ((array)$http->resp_headers as $name => $value) {
            if (strtolower($name) !== 'link') continue;
            foreach ((array)$value as $header) {
                foreach ($this->parseLinkHeader($header) as $link) {
                    $this->recordEndpoint($found, $link['rel'], $link['href'], $identity);
                }
            }
        }

        if (class_exists(DOMDocument::class)) {
            $document = new DOMDocument();
            $previous = libxml_use_internal_errors(true);
            $document->loadHTML('<?xml encoding="utf-8" ?>' . (string)$http->resp_body, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
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

        if (!$found['authorization_endpoint']) {
            throw new RuntimeException($this->getLang('noauthorizationendpoint'));
        }

        return $found;
    }

    /** Validate and store a discovered endpoint. */
    private function recordEndpoint(array &$found, $rel, $href, $base)
    {
        if (!in_array(strtolower($rel), ['authorization_endpoint', 'token_endpoint'], true) || $href === '') return;
        $url = $this->resolveUrl($base, $href);
        $parts = parse_url($url);
        if (!$parts || empty($parts['host']) || strtolower($parts['scheme'] ?? '') !== 'https') {
            throw new RuntimeException($this->getLang('endpointmustbehttps'));
        }
        $this->assertPublicHost(strtolower(trim($parts['host'], '[]')));
        $found[strtolower($rel)] = $url;
    }

    /** Resolve an endpoint reference against the identity URL. */
    private function resolveUrl($base, $reference)
    {
        if (preg_match('~^https://~i', $reference)) return $reference;
        if (strpos($reference, '//') === 0) return 'https:' . $reference;
        $baseParts = parse_url($base);
        $origin = $baseParts['scheme'] . '://' . $baseParts['host'] . (isset($baseParts['port']) ? ':' . $baseParts['port'] : '');
        if (strpos($reference, '/') === 0) return $origin . $reference;
        $path = $baseParts['path'] ?? '/';
        return $origin . rtrim(dirname($path), '/') . '/' . $reference;
    }

    /** Parse Link header entries for rel and href parameters. */
    private function parseLinkHeader($header)
    {
        $links = [];
        if (preg_match_all('/<([^>]+)>\s*((?:;[^,]*)*)/', (string)$header, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                if (preg_match('/(?:^|;)\s*rel\s*=\s*"?([^";]+)"?/i', $match[2], $relMatch)) {
                    foreach (preg_split('/\s+/', trim($relMatch[1])) as $rel) {
                        $links[] = ['href' => trim($match[1]), 'rel' => $rel];
                    }
                }
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
