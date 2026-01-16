<?php

//declare(strict_types=1);

namespace cryodrift\user;

use cryodrift\fw\Config;
use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\Crypt;
use cryodrift\fw\interface\Configs;
use cryodrift\fw\interface\Handler;
use cryodrift\fw\Router;

class Auth implements Handler, Configs
{
    // need to be logged in to show the route
    const string CONFIG_NEEDUSER = 'protect';
    // when we have a session we use it, but we dont need to be logged in to show the route
    const string CONFIG_USESESSION = 'usesession';

    public function __construct(protected array $protect, protected array $usesession, protected string $cookiepassword, protected bool $https)
    {
        if (!Config::isCli() && !headers_sent()) {
            ini_set('session.use_cookies', 0);
        }
    }

    public function handle(Context $ctx): Context
    {
        foreach (Router::pathParts($ctx->request()->path()) as $path) {
            if (in_array($path, $this->protect)) {
                $ctx->response()->setStatusFinal();
                if (Config::isCli()) {
                    try {
                        if ($ctx->user()) {
                            $ctx->response()->setStatusInvalid();
                        }
                    } catch (\Exception $ex) {
                        //ignore missing user here
                    }
                } else {
                    if ($this->initSession() && Core::getValue('password', $_SESSION, false) && Core::getValue('user', $_SESSION, false)) {
                        if ($ctx->request()->isPost()) {
                            if (hash_equals(Core::getValue('csrf', $_SESSION), Core::getValue('HTTP_X_CSRF_TOKEN', $_SERVER))) {
                                $ctx->response()->setStatusInvalid();
                                session_write_close();
                            }
                        } else {
                            $ctx = $this->sendNewCsrf($ctx);
                            $ctx->response()->setStatusInvalid();
                            session_write_close();
                        }
                    }
                }
            }
        }
        if ($ctx->response()->isValid()) {
            foreach (Router::pathParts($ctx->request()->path()) as $path) {
                if (in_array($path, $this->usesession)) {
                    if ($this->initSession() && Core::getValue('password', $_SESSION, false) && Core::getValue('user', $_SESSION, false)) {
                        $ctx = $this->sendNewCsrf($ctx);
                        $ctx->response()->setStatusInvalid();
                        session_write_close();
                    } else {
                        session_abort();
                        $_SESSION = [];
                    }
                }
            }
        }
        if ($ctx->response()->isFinal()) {
            if (Config::isCli()) {
                $ctx->response()->setContent('Missing param -sessionuser=""');
            } else {
                if ($ctx->request()->path()->getString()) {
                    $ctx->response()->setHeaders(['location: /']);
                }
            }
        }
        return $ctx;
    }

    private function sendNewCsrf(Context $ctx): Context
    {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        $ctx->response()->addCookie('csrftoken', $_SESSION['csrf'], 0, '/', Web::getHttpHost(), $this->https, false);
        return $ctx;
    }

    public function remCsrf(Context $ctx): Context
    {
        $ctx->response()->addCookie('csrftoken', '', -1, '/', Web::getHttpHost(), $this->https, false);
        return $ctx;
    }

    public function initSession(): bool
    {
//        Core::log(__METHOD__, Core::getValue(session_name(), $_COOKIE));
        if ($sesskey = Core::getValue(session_name(), $_COOKIE)) {
            $sessid = Crypt::decryptPw($sesskey, $this->cookiepassword);
            if ($sessid) {
                session_id($sessid);
                session_start();
                return true;
            }
        }
        return false;
    }

    public static function addConfigs(Context $ctx, array $data, string $typ = self::CONFIG_NEEDUSER): void
    {
        $config = $ctx->config()->getHandler(self::class);
        $config[$typ] = array_merge(Core::getValue($typ, $config, []), $data);
        $config[$typ] = array_unique($config[$typ]);
        $ctx->config()->addHandler(self::class, $config);
    }

}
