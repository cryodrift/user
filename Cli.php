<?php

//declare(strict_types=1);

namespace cryodrift\user;


use cryodrift\fw\cli\Colors;
use PragmaRX\Google2FA\Google2FA;
use cryodrift\user\db\Repository;
use cryodrift\fw\cli\ParamHidden;
use cryodrift\fw\Config;
use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\interface\Handler;
use cryodrift\fw\interface\Testable;
use cryodrift\fw\Main;
use cryodrift\fw\trait\CliHandler;

class Cli implements Handler, Testable
{

    use CliHandler;

    private array $user = [];

    public function __construct(protected Repository $db, protected Config $config)
    {
    }

    public function handle(Context $ctx): Context
    {
        $ctx->response()->setStatusFinal();
        return $this->handleCli($ctx);
    }

    /**
     * @cli register a new user with 2fa
     * @cli param: -user="" (username)
     * @cli param: [-password] (leaf blank to get prompted)
     */
    public function register(Context $ctx, string $user, ParamHidden $password): string
    {
        Core::echo(__METHOD__, 'load', Core::time());
        $out = '';
        if ($this->db->connect($user, (string)$password)) {
            $out = 'User Authenticated';
            Core::echo(__METHOD__, 'verify took:', Core::time());
        } else {
            if (strlen((string)$password) >= Core::getValue('passwordlen', $this->config, 6)) {
                require_once Main::path('vendor/autoload.php');
                $tfa = new Google2FA();
                $this->db->set2faSecret($tfa->generateSecretKey());
                Core::echo(__METHOD__, 'secret took:', Core::time());
                $this->db->write();
                Core::echo(__METHOD__, 'write took:', Core::time());
                $out = 'OK';
            } else {
                throw new \Exception(Core::toLog(Colors::get('[ERROR]', Colors::FG_light_red), 'Password too short: missing ' . Core::getValue('passwordlen', $this->config, 6) - strlen((string)$password) . ' chars!'));
            }
        }
        return $out;
    }

    /**
     * @cli test db
     * @cli param: -user="" (username)
     * @cli param: -password (leaf blank to get prompted)
     */
    protected function testdb(string $user, ParamHidden $password): array
    {
        Core::log(__METHOD__, $user, $password, $this->db->connect($user, (string)$password));
        $secret = $this->db->get('secret', '', true);
        if ($secret) {
            $this->db->set2faSecret($secret);
        }
        Core::log(__METHOD__, 'secret', $this->db->get2faSecret());
//        Core::log(__METHOD__, 'write', $this->db->write());
        return Core::log();
    }

    /**
     * @cli change users password
     * @cli param: -user="" (username)
     * @cli param: -password (leaf blank to get prompted)
     * @cli param: -newpassword (leaf blank to get prompted)
     */
    public function changepw(string $user, ParamHidden $password, ParamHidden $newpassword): array
    {
        $this->db->connect($user, (string)$password);
        if (strlen((string)$newpassword) >= Core::getValue('passwordlen', $this->config, 6)) {
            return $this->db->write((string)$newpassword);
        }
        return [];
    }

    /**
     * @cli check login
     * @cli param: -user="" (username)
     * @cli param: -password (leaf blank to get prompted)
     * @cli param: -code (2fa number)
     */
    public function login(string $user, ParamHidden $password, string $code = ''): array
    {
        if (strlen((string)$password) >= Core::getValue('passwordlen', $this->config, 6)) {
            if ($this->db->connect($user, (string)$password)) {
                if (Core::getValue('use2fa', $this->config, true)) {
                    require_once Main::path('vendor/autoload.php');
                    $tfa = new Google2FA();
                    if ($tfa->verifyKey($this->db->get2faSecret(), $code)) {
                        return ['login' => 'OK', 'user' => $user];
                    }
                } else {
                    return ['login' => 'OK', 'user' => $user];
                }
            }
        }
        return [];
    }

    /**
     * @cli show current 2fa code
     * @cli param: -secret
     */
    public function getcode(string $secret): string
    {
        require_once Main::path('vendor/autoload.php');
        $tfa = new Google2FA();
        return $tfa->getCurrentOtp($secret);
    }

    /**
     * @cli show users secret
     * @cli param: -user="" (username)
     * @cli param: -password (leaf blank to get prompted)
     */
    public function getsecret(string $user, ParamHidden $password): string
    {
        $this->db->connect($user, (string)$password);
        return $this->db->get2faSecret();
    }

    /**
     * @cli run to test if register, getsecret, getcode, login is working
     */
    public function test(Context $ctx): array
    {
        $out = [];
        try {
            $this->db->delete('test');
            $out[] = $this->register($ctx, 'test', new ParamHidden($ctx, 'password', 'test123456'));
            $out[] = $this->testdb('test', new ParamHidden($ctx, 'password', 'test123456'));
            $secret = $this->getsecret('test', new ParamHidden($ctx, 'password', 'test123456'));
            $code = $this->getcode($secret);
            $out[] = $this->login('test', new ParamHidden($ctx, 'password', 'test123456'), $code);
            $out[] = $this->db->getData();
            $fakectx = clone $ctx;
            $fakectx->request()->setParam('post', true);
            $web = (fn(): Web => Core::newObject(Web::class, $fakectx))();
            $secretkey = $this->config['secretkey'];
            $query = $this->getcode($secretkey);
            $fakectx->request()->setVar('query', $query);
            $out[] = $web->index(...Core::getParams($web, 'index', [], $fakectx))->response()->getHeaders();
            $this->db->delete('test');
        } catch (\Exception $ex) {
            Core::echo(__METHOD__, $ex->getMessage(), $secret, $secretkey);
        }
        return $out;
    }

    /**
     * @cli generate a random 2fa key
     */
    public function keygen(): string
    {
        require_once Main::path('vendor/autoload.php');
        $tfa = new Google2FA();
        return $tfa->generateSecretKey();
    }

    /**
     * @cli create or modify mail account
     * @cli -type="" (pop3smtp|pop3|smtp)
     * @cli -host="" (hostname eg smtp.localhost.lan)
     * @cli -name="" (username)
     * @cli -pass="" (password)
     *
     */
    public function mailaccount(ParamType $type, ParamNotEmpty $name, ParamNotEmpty $host, ParamHidden $pass, AccountStorage $storage): array
    {
        $storage->update($host, ['type' => (string)$type, 'name' => (string)$name, 'host' => (string)$host, 'password' => (string)$pass], 4);
        return $storage->load();
    }

}
