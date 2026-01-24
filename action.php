<?php
if(!defined('DOKU_INC')) return; // only run inside DokuWiki

class action_plugin_oauthindie extends DokuWiki_Action_Plugin {
    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('DOKUWIKI_STARTED', 'AFTER', $this, 'handle_start');
    }

    public function handle_start(Doku_Event $event, $param) {
        $act = $_GET['oauthindie'] ?? null;
        if(!$act) return;

        switch($act) {
            case 'start':
                require_once __DIR__ . '/start.php';
                exit;
            case 'callback':
                require_once __DIR__ . '/callback.php';
                exit;
        }
    }
}
