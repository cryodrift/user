<?php

//declare(strict_types=1);

namespace cryodrift\user\db;


use cryodrift\fw\Core;
use cryodrift\fw\Crypt;

/**
 * this is string only because its only a key storage for faster access
 */
class Repository
{

    private string $pathname;
    private array $data = [];
    private string $password;
    private string $masterkey;

    public function __construct(protected string $storagedir)
    {
    }

    public function connect(string $name, string $password): bool
    {
        $this->pathname = $this->storagedir . md5($name) . '.ser';
        $this->password = $password;
        $data = null;
        if (file_exists($this->pathname)) {
            $data = unserialize(file_get_contents($this->pathname));
        } else {
            Core::echo(__METHOD__, 'missing file: ' . $this->pathname);
        }
        if (empty($data)) {
            $this->data = ['passhash' => password_hash($password, PASSWORD_DEFAULT)];
            $this->masterkey = Crypt::getRandomUuid();
        } else {
            $this->data = $data;
            $this->masterkey = Core::getValue('masterkey', $data, $password, true);
            if (password_verify($password, Core::getValue('passhash', $data))) {
                if (isset($this->data['masterkey'])) {
                    $this->masterkey = Crypt::decryptPw($this->data['masterkey'], $password);
                }
                return true;
            }
        }
        return false;
    }

    public function set(string $name, string $data): void
    {
        if (!in_array($name, ['masterkey', 'passhash'])) {
            if ($data === '') {
                unset($this->data[$name]);
            } else {
                $this->data[$name] = Crypt::encryptPw($data, $this->masterkey);
            }
        }
    }

    public function get(string $name, string $default = '', bool $encryptwithpassword = false): string
    {
        if (!in_array($name, ['masterkey', 'passhash'])) {
            if ($encryptwithpassword) {
                $key = $this->password;
            } else {
                $key = $this->masterkey;
            }
            return Crypt::decryptPw(Core::getValue($name, $this->data, $default), $key);
        } else {
            return $default;
        }
    }

    public function set2faSecret(string $data): void
    {
        $this->set('secret', $data);
    }

    public function get2faSecret(): string
    {
        return $this->get('secret');
    }

    public function write(string $password = ''): array
    {
        if (password_verify($this->password, Core::getValue('passhash', $this->data))) {
            Core::echo(__METHOD__, $this->data);
            if ($password) {
                $this->password = $password;
                $this->data['passhash'] = password_hash($password, PASSWORD_DEFAULT);
            }
            if (!isset($this->data['masterkey'])) {
                $this->data['masterkey'] = Crypt::encryptPw($this->masterkey, $this->password);
            }
            Core::fileWrite($this->pathname, serialize($this->data), 0, true);
            return $this->data;
        } else {
            return $this->data;
        }
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function delete(string $name)
    {
        $pathname = $this->storagedir . md5($name) . '.ser';
        Core::echo(__METHOD__, $pathname, file_exists($pathname));
        if (file_exists($pathname)) {
            unlink($pathname);
        }
    }


}
