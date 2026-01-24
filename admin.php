<?php
if(!defined('DOKU_INC')) die();

class admin_plugin_oauthindie extends DokuWiki_Admin_Plugin {

    public function forAdminOnly(){
        return false; // allow non-admins to access if desired; change to true to restrict
    }

    public function handle() {
        // nothing to handle here; the form POSTS to the start route
    }

    public function html() {
        $base = '';
        global $conf;
        if(!empty($conf['baseurl'])) $base = rtrim($conf['baseurl'], '/');
        echo '<h2>oauthindie — Sign In</h2>';
        echo '<p>Use this form to start an IndieAuth sign-in flow.</p>';
        echo '<form action="?oauthindie=start" method="post">';
        echo '<label for="url">Identity URL:</label> ';
        $val = 'https://orwell.fun';
        echo '<input id="url" name="url" type="url" value="'.$val.'" size="50" required /> ';
        echo '<button type="submit">Sign In</button>';
        echo '</form>';
    }
}
