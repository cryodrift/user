<?php

namespace cryodrift\user;

use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\interface\Param;

class ParamType implements Param
{

    private string $value = '';

    public function __construct(Context $ctx, string $name, string $value)
    {
        if (in_array($value, ['pop3smtp', 'pop3', 'smtp'])) {
            $this->value = $value;
        } else {
            throw new \Exception(Core::toLog(__METHOD__, ['wrong type! allowed types: pop3, smtp,pop3smtp']));
        }
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
