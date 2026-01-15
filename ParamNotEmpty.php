<?php

namespace cryodrift\user;

use cryodrift\fw\Context;
use cryodrift\fw\Core;
use cryodrift\fw\interface\Param;

class ParamNotEmpty implements Param
{

    private string $value = '';

    public function __construct(Context $ctx, string $name, string $value)
    {
        if ($value) {
            $this->value = $value;
        } else {
            throw new \Exception(Core::toLog(__METHOD__, ['Param must not be empty!', $name]));
        }
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
