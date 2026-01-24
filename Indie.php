<?php

/**
 * DokuWiki Plugin oauthindie (Indie Service Component)
 *
 * @license GPL 3 http://www.gnu.org/licenses/gpl-3.0.html
 * @author  Tassoman <tassoman@gmail.com>
 */

namespace dokuwiki\plugin\oauthindie;

use dokuwiki\plugin\oauth\Service\AbstractOAuth2Base;
use OAuth\Common\Http\Uri\Uri;

/**
 * Custom Service for Indie oAuth
 */
class Indie extends AbstractOAuth2Base
{
    /** @inheritdoc */
    public function needsStateParameterInAuthUrl() {
        $plugin = plugin_load('helper', 'oauthgeneric');
        return 0 !== $plugin->getConf('needs-state');
    }

    /** @inheritdoc */
    public function getAuthorizationEndpoint()
    {
        $plugin = plugin_load('helper', 'oauthgeneric');
        return new Uri($plugin->getConf('authurl'));
    }

    /** @inheritdoc */
    public function getAccessTokenEndpoint()
    {
        $plugin = plugin_load('helper', 'oauthgeneric');
        return new Uri($plugin->getConf('tokenurl'));
    }

    /**
     * @inheritdoc
     */
    protected function getAuthorizationMethod()
    {
        $plugin = plugin_load('helper', 'oauthgeneric');

        return (int) $plugin->getConf('authmethod');
    }
}
