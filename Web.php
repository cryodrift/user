<?php

//declare(strict_types=1);

namespace cryodrift\user;

use PragmaRX\Google2FA\Google2FA;
use cryodrift\user\db\Repository;
use cryodrift\fw\Config;
use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\Crypt;
use cryodrift\fw\HtmlUi;
use cryodrift\fw\interface\Handler;
use cryodrift\fw\trait\PageHandler;
use cryodrift\fw\trait\WebHandler;
use Exception;

class Web implements Handler
{

    use WebHandler;
    use PageHandler;

    protected string $httphost;

    public function __construct(
      private readonly Cli $cli,
      private readonly Repository $db,
      private readonly string $cookiepassword,
      private readonly bool $https,
      private readonly bool $hidelogin,
      private readonly Config $config
    ) {
        $this->httphost = self::getHttpHost();
    }

    public static function getHttpHost(): string
    {
        // Use a consistent domain across all setcookie() calls
        // Normalize cookie domain to avoid duplicates like `.gfw.localhost` vs `gfw.localhost`
        $host = (string)Core::getValue('HTTP_HOST', $_SERVER);
        // drop port if present
        $host = explode(':', $host)[0];
        // strip any leading dots (obsolete in RFC 6265 and can create variants)
        // it seems browser prefixes with dot anyway
        // normalize case
        return strtolower(ltrim($host, '.'));
    }

    public function handle(Context $ctx): Context
    {
        if ($this->httphost) {
            return $this->handleWeb($ctx);
        } else {
            Core::echo(__METHOD__, 'empty httphost', $ctx->request()->path());
            return $ctx;
        }
    }

    public function userSignIn(Context $ctx): Context
    {
        $info = $this->cli->login(...Core::getParams($this->cli, 'login', $ctx->request()->vars(), $ctx));
        if (Core::getValue('login', $info) === 'OK') {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }
            $_SESSION = [];
            $_SESSION['password'] = $ctx->request()->vars('password');
            $_SESSION['user'] = $ctx->request()->vars('user');
//            Core::echo(__METHOD__, $info, $_SESSION);
            session_regenerate_id();
            session_write_close();
            $sesskey = Crypt::encryptPw(session_id(), $this->cookiepassword);
            $ctx->response()->addCookie(session_name(), '', -1, '/login', $this->httphost, $this->https, true);
            $ctx->response()->addCookie(session_name(), $sesskey, 0, '/', $this->httphost, $this->https, true);
            $ctx->response()->setStatusFinal();
            $ctx->response()->setHeaders(['location: /']);
            return $ctx;
        }
        throw new \Exception('Unauthorized', 401);
    }

    /**
     * @web login
     */
    public function login(Context $ctx): Context
    {
        $sesskey = Core::getValue(session_name(), $_COOKIE);
        if (!str_ends_with($sesskey, '=')) {
            session_id($sesskey);
            Core::echo(__METHOD__, 'found:', 'sessionid:' . session_id(), 'session_name:', session_name(), 'COOKIE:', $_COOKIE);
        }
        if (!session_start()) {
            Core::echo(__METHOD__, 'SESSIONERROR:', 'sessionid:' . session_id(), 'session_name:', session_name(), 'COOKIE:', $_COOKIE);
        }
        if ($this->hidelogin === false || ($ctx->config()->isCli() && $ctx->request()->hasParam('fakelogin'))) {
            $_SESSION['auth'] = true;
        }
        if (Core::getValue('auth', $_SESSION) === true) {
            if ($ctx->request()->isPost()) {
                try {
                    $ctx = $this->userSignIn($ctx);
                    $referer = $ctx->request()->vars('redirect', '/');
                    if (str_starts_with($referer, '/')) {
                        $ctx->response()->setHeaders(['location: ' . $referer]);
                    }
                } catch (Exception $ex) {
                }
            }
            $html = HtmlUi::fromFile('user/ui/login.html');
            $html->setAttributes(['user' => $ctx->request()->vars('user')]);
            if (Core::getValue('use2fa', $this->config, true)) {
                $html->setAttributes(['codeblock' => [[]]]);
            } else {
                $html->setAttributes(['codeblock' => []]);
            }
            $this->outHelperAttributes(['scriptblock' => [[]]]);
            $ctx = $this->handlePage($ctx, $this->config);
            $this->outHelperAttributes(['content' => $html]);
        } else {
            session_destroy();
            $ctx = $this->removeCookie($ctx);
//            setcookie(session_name(), '', -1, '/', $this->httphost, $this->https, true);
            $referer = $ctx->request()->vars('redirect', '/');
            if (!str_starts_with($referer, '/')) {
                $referer = '/';
            }
            $ctx->response()->setHeaders(['location: ' . $referer]);
        }
        return $ctx;
    }


    /**
     * @web logout
     */
    public function logout(Context $ctx, Auth $auth): Context
    {
        $ctx = $this->removeCookie($ctx);
        $ctx = $auth->remCsrf($ctx);
        $ctx->response()->setStatusFinal();
        session_start();
        session_destroy();
        session_write_close();
        $referer = $ctx->request()->vars('redirect', '/');
        if (!str_starts_with($referer, '/')) {
            $referer = '/';
        }
        $ctx->response()->setHeaders(['location: ' . $referer]);
        return $ctx;
    }


    /* settings for user
    change password
    fetch 2fa key
    change email
    read some stats
   */
    /**
     * @web user admin settings
     */
    protected function admin(Context $ctx): Context
    {
        $ui = HtmlUi::fromFile('user/ui/admin.html');
        $ctx = $this->handlePage($ctx, $this->config);
        $this->outHelperAttributes(['scriptblock' => [[]]]);
        $ctx->response()->getContent()->setAttributes(['content' => $ui]);
        return $ctx;
    }

    /**
     * @web handle startpage
     * show page with input to collect authenticator token
     */
    public function index(Context $ctx): Context
    {
        if ($ctx->request()->isPost() && $search = $ctx->request()->vars('query')) {
            require_once 'vendor/autoload.php';
            $tfa = new Google2FA();
            $ctx = $this->removeCookie($ctx);
            $secretkey = $this->config->secretkey;
            $timeout = $this->config->timeout;

            if ($tfa->verifyKey($secretkey, $search)) {
                session_id(Core::getValue(session_name(), $_COOKIE));
                session_start();
                session_regenerate_id();
                $ctx->response()->addCookie(session_name(), session_id(), time() + $timeout, '/user/login', $this->httphost, true, true);
                $_SESSION['auth'] = true;
                $ctx->response()->setStatusFinal();
                $ctx->response()->setRedirect('/user/login');
                return $ctx;
            }
        }

        if ($this->hasSession($ctx)) {
            $ui = HtmlUi::fromFile('user/ui/menu.html');
            $ui->setAttributes(['user' => $ctx->user(false)]);
            $this->outHelperAttributes(['scriptblock' => [[]]]);
        } else {
            if ($this->hidelogin) {
                $this->outHelperAttributes(['scriptblock' => []]);
                $ui = HtmlUi::fromFile('user/ui/search.html');
            } else {
                $ctx->response()->setStatusFinal();
                $ctx->response()->setRedirect('/user/login');
                return $ctx;
            }
        }
        $ctx = $this->handlePage($ctx, $this->config);
        $this->outHelperAttributes(['content' => $ui]);
        return $this->outHelper($ctx, $ctx);
    }

    /**
     * @web handle api calls
     */
    protected function api(Context $ctx, string $command, AccountStorage $astore): Context
    {
        $this->docvar = 'api';
        $map = ['2fa' => 'twofactorkey', 'password' => 'changepassword', 'email' => 'emailaccounts', 'emaildelete' => 'emaildelete'];
        if (in_array($command, array_keys($map))) {
            $method = $map[$command];
            $ctx->response()->setContent($this->$method($ctx, $astore));
        }

        return $ctx;
    }

    /**
     * @api
     */
    protected function twofactorkey(Context $ctx): HtmlUi
    {
        $ui = HtmlUi::fromFile('user/ui/2fa.html');
        $cli = Core::newObject(Cli::class, $ctx);
        $ui->setAttributes(['content' => $cli->getsecret(...Core::getParams($cli, 'getsecret', $_SESSION, $ctx))]);
        return $ui;
    }

    /**
     * @api
     */
    protected function changepassword(Context $ctx): HtmlUi
    {
        $ui = HtmlUi::fromFile('user/ui/password.html');
        $user = $ctx->user(false);
        $ui->setAttributes(['user' => $user]);

        $req = $ctx->request();
        $values = Core::extractKeys(Core::jsonRead($ctx->request()->vars('value', '[[]]')), ['old_password', 'new_password']);
        $old_password = Core::getValue('old_password', $values);
        $new_password = Core::getValue('new_password', $values);
        $ui->setAttributes(['answer' => '']);
        $ui->setAttributes(['form' => [[]]]);
        if ($req->isPost() && $old_password && $new_password) {
            $params = Core::getParams($this->cli, 'changepw', ['user' => Core::getValue('user', $_SESSION), 'password' => $old_password, 'newpassword' => $new_password], $ctx);
            if (count($this->cli->changepw(...$params)) > 0) {
                $ui->setAttributes(['answer' => 'Password changed!'], true);
                $ui->setAttributes(['form' => []]);
            }
        }
        return $ui;
    }

    /**
     * @api
     */
    protected function emailaccounts(Context $ctx, AccountStorage $astore): HtmlUi
    {
        $ui = HtmlUi::fromFile('user/ui/email.html');

        $answer = '';
        $accounts = $astore->load();

        if ($ctx->request()->isPost()) {
            $data = Core::extractKeys(Core::jsonRead($ctx->request()->vars('value', '[[]]')), ['type', 'name', 'host', 'password']);
            $host = Core::getValue('host', $data);
            $accounts = $astore->update($host, $data, 4);
        }

        $accounts = Core::addData($accounts, function ($a) use ($ctx) {
            $a['id'] = Crypt::encryptPw(Core::getValue('host', $a), $ctx->password());
            return $a;
        });

        $ui->setAttributes(['accounts' => $accounts]);
        $ui->setAttributes(['answer' => $answer]);

        foreach (['host' => '', 'name' => '', 'password' => '', 'type' => ''] as $k => $v) {
            $data += [$k => $v];
        }
        $ui->setAttributes($data);
        return $ui;
    }

    /**
     * @api
     */
    protected function emaildelete(Context $ctx, AccountStorage $astore): HtmlUi
    {
        $ui = HtmlUi::fromString('{{test}}');

        $answer = '';
        if ($ctx->request()->isPost()) {
            $data = Core::extractKeys(Core::jsonRead($ctx->request()->vars('data-id', '[[]]')), ['data-id']);
            $host = Crypt::decryptPw(Core::getValue('data-id', $data), $ctx->password());
            if ($host) {
                $astore->delete($host);
                $answer = 'Deleted ' . $host;
            }
        }

        $ui->setAttributes(['test' => $answer]);
        return $ui;
    }

    private function removeCookie(Context $ctx): Context
    {
        $ctx->response()->addCookie(session_name(), '', -1, '/', $this->httphost, $this->https, true);
        return $ctx;
    }

    private function hasSession(Context $ctx): bool
    {
        $hassession = false;
        if (Config::isCli()) {
            try {
                return (bool)$ctx->user();
            } catch (\Exception $ex) {
                Core::echo(__METHOD__, $ex->getMessage());
                return false;
            }
        } else {
            if (Core::getValue(session_name(), $_COOKIE)) {
                $auth = Core::newObject(Auth::class, $ctx);
                $hassession = $auth->initSession();
            }
            return $hassession && Core::getValue('user', $_SESSION);
        }
    }

}
