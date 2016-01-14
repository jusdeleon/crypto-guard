<?php

namespace Coreproc\CryptoGuard\Facades;

use Illuminate\Support\Facades\Facade;

class CryptoGuard extends Facade
{

    public static function getFacadeAccessor()
    {
        return 'cryptoguard';
    }

}