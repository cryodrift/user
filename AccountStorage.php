<?php

//declare(strict_types=1);

namespace cryodrift\user;


use cryodrift\user\db\Repository;
use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\Crypt;

/**
 * TODO refactor to ArrayStorage
 */
class AccountStorage
{
    const string DATAKEY = 'accountstorage';
    private string $mailspathname;

    public function __construct(Context $ctx, protected Repository $db, protected string $storagedir)
    {
        $this->storagedir = $storagedir . $ctx->user() . '/';
        $this->db->connect($ctx->user(false), $ctx->password());

        $mailspw = $this->db->get(self::DATAKEY);
        $this->mailspathname = $this->storagedir . 'email.ser';
        if (empty($mailspw)) {
            $mailspw = Crypt::getRandomUuid();
            $this->db->set(self::DATAKEY, $mailspw);
            $this->db->write();
        }
    }

    public function delete(string $name)
    {
        $data = $this->load();
        if ($name) {
            unset($data[$name]);
            Core::fileWrite($this->mailspathname, Crypt::encryptPw(serialize($data), $this->db->get(self::DATAKEY)));
        }
        return $data;
    }

    public function update(string $name, array $value, int $items = 3): array
    {
        $data = $this->load();
        if ($name && count($value) === $items) {
            $data[$name] = $value;
            Core::fileWrite($this->mailspathname, Crypt::encryptPw(serialize($data), $this->db->get(self::DATAKEY)),0,true);
        }
        return $data;
    }

    public function load(): array
    {
        try {
            $data = Core::fileReadOnce($this->mailspathname);
            $out = unserialize(Crypt::decryptPw($data, $this->db->get(self::DATAKEY)));
            if (is_array($out)) {
                return $out;
            }
        } catch (\Exception $ex) {
            Core::echo(__METHOD__, $ex->getMessage(), $this->mailspathname);
        }
        return [];
    }
}
