<?php

use dokuwiki\Extension\AuthPlugin;
require_once __DIR__ . '/lib/oauthindie_helpers.php';

/**
 * DokuWiki Plugin oauthindie (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author Tassoman <tassoman@gmail.com>
 */
class auth_plugin_oauthindie extends AuthPlugin
{
    /** @inheritDoc */
    public function __construct()
    {
        parent::__construct(); // for compatibility

        // FIXME set capabilities accordingly
        //$this->cando['addUser']     = false; // can Users be created?
        //$this->cando['delUser']     = false; // can Users be deleted?
        //$this->cando['modLogin']    = false; // can login names be changed?
        //$this->cando['modPass']     = false; // can passwords be changed?
        //$this->cando['modName']     = false; // can real names be changed?
        //$this->cando['modMail']     = false; // can emails be changed?
        //$this->cando['modGroups']   = false; // can groups be changed?
        //$this->cando['getUsers']    = false; // can a (filtered) list of users be retrieved?
        //$this->cando['getUserCount']= false; // can the number of users be retrieved?
        //$this->cando['getGroups']   = false; // can a list of available groups be retrieved?
        //$this->cando['external']    = false; // does the module do external auth checking?
        //$this->cando['logout']      = true; // can the user logout again? (eg. not possible with HTTP auth)
            // Declare capabilities: this plugin performs external authentication
            $this->cando['addUser']     = false;
            $this->cando['delUser']     = false;
            $this->cando['modLogin']    = false;
            $this->cando['modPass']     = false;
            $this->cando['modName']     = false;
            $this->cando['modMail']     = false;
            $this->cando['modGroups']   = false;
            $this->cando['getUsers']    = false;
            $this->cando['getUserCount']= false;
            $this->cando['getGroups']   = false;
            $this->cando['external']    = true; // plugin does external auth checking
            $this->cando['logout']      = true;

        // FIXME intialize your auth system and set success to true, if successful
        $this->success = true;
    }

    /** @inheritDoc */
    // public function logOff()
    // {
    // }

    /** @inheritDoc */
    //public function trustExternal($user, $pass, $sticky = false)
    //{
        /* some example:

        global $USERINFO;
        global $conf;
        $sticky ? $sticky = true : $sticky = false; //sanity check

        // do the checking here

        // set the globals if authed
        $USERINFO['name'] = 'FIXME';
        $USERINFO['mail'] = 'FIXME';
        $USERINFO['grps'] = array('FIXME');
        $_SERVER['REMOTE_USER'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        return true;

        */
    //}

    /** @inheritDoc */
    public function checkPass($user, $pass)
    {
        // FIXME implement password check, alternatively implement trustExternal()
        return false; // return true if okay
    }

    /** @inheritDoc */
    public function trustExternal($user, $pass, $sticky = false)
    {
        // Accept external authentication information populated by the IndieAuth callback.
        global $USERINFO;

        if(session_status() !== PHP_SESSION_ACTIVE) session_start();

        // Prefer DokuWiki session format
        $dokuCookie = defined('DOKU_COOKIE') ? DOKU_COOKIE : null;
        $auth = false;
        if($dokuCookie && !empty($_SESSION[$dokuCookie]['auth'])){
            $auth = $_SESSION[$dokuCookie]['auth'];
        } elseif(!empty($_SESSION['oauthindie_auth'])){
            $auth = $_SESSION['oauthindie_auth'];
        }

        if(!$auth) return false;

        $sessUser = is_array($auth) ? ($auth['user'] ?? null) : null;
        if(function_exists('oauthindie_log')) oauthindie_log("trustExternal: session user=".var_export($sessUser, true));
        if($user !== $sessUser) {
            if(function_exists('oauthindie_log')) oauthindie_log("trustExternal: mismatch user param=".var_export($user, true));
            return false;
        }

        // populate $USERINFO and server/session entries expected by DokuWiki
        $USERINFO = $auth['info'] ?? ['name' => $sessUser, 'mail' => '', 'grps' => ['user']];
        if($dokuCookie){
            $_SESSION[$dokuCookie]['auth']['user'] = $sessUser;
            $_SESSION[$dokuCookie]['auth']['pass'] = $_SESSION[$dokuCookie]['auth']['pass'] ?? bin2hex(random_bytes(12));
            $_SESSION[$dokuCookie]['auth']['info'] = $USERINFO;
        }
        $_SERVER['REMOTE_USER'] = $sessUser;

        return true;
    }

    /** @inheritDoc */
    public function getUserData($user, $requireGroups = true)
    {
        /*
        FIXME implement and return something like this
        $userinfo = [
            'name' => 'Jon Doe',
            'mail' => 'doe@example.com',
            'grps' => ['user', 'admin']
        ];
        */

            if(session_status() !== PHP_SESSION_ACTIVE) session_start();
            $dokuCookie = defined('DOKU_COOKIE') ? DOKU_COOKIE : null;
            $auth = null;
            if($dokuCookie && !empty($_SESSION[$dokuCookie]['auth'])){
                $auth = $_SESSION[$dokuCookie]['auth'];
            } elseif(!empty($_SESSION['oauthindie_auth'])){
                $auth = $_SESSION['oauthindie_auth'];
            }
            if(!$auth) return false;
            $sessUser = is_array($auth) ? ($auth['user'] ?? null) : null;
            if(function_exists('oauthindie_log')) oauthindie_log("getUserData: lookup for user=".var_export($user, true)." found session user=".var_export($sessUser, true));
            if($sessUser !== $user) return false;
            return $auth['info'] ?? false;
    }

    /** @inheritDoc */
    //public function createUser($user, $pass, $name, $mail, $grps = null)
    //{
        // FIXME implement
    //    return null;
    //}

    /** @inheritDoc */
    //public function modifyUser($user, $changes)
    //{
        // FIXME implement
    //    return false;
    //}

    /** @inheritDoc */
    //public function deleteUsers($users)
    //{
        // FIXME implement
    //    return false;
    //}

    /** @inheritDoc */
    //public function retrieveUsers($start = 0, $limit = 0, $filter = null)
    //{
        // FIXME implement
    //    return array();
    //}

    /** @inheritDoc */
    //public function getUserCount($filter = array())
    //{
        // FIXME implement
    //    return 0;
    //}

    /** @inheritDoc */
    //public function addGroup($group)
    //{
        // FIXME implement
    //    return false;
    //}

    /** @inheritDoc */
    //public function retrieveGroups($start = 0, $limit = 0)
    //{
        // FIXME implement
    //    return array();
    //}

    /** @inheritDoc */
    public function isCaseSensitive()
    {
        return true;
    }

    /** @inheritDoc */
    public function cleanUser($user)
    {
        return $user;
    }

    /** @inheritDoc */
    public function cleanGroup($group)
    {
        return $group;
    }

    /** @inheritDoc */
    //public function useSessionCache($user)
    //{
      // FIXME implement
    //}
}
