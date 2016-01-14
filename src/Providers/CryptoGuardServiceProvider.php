<?php

namespace Coreproc\CryptoGuard\Providers;
use Illuminate\Support\ServiceProvider;
use Coreproc\CryptoGuard\CryptoGuard;

class CryptoGuardServiceProvider extends ServiceProvider
{

    public function register()
    {
        $this->publishes([
            dirname(__DIR__) . '..\..\config\crypto_guard.php' => config_path('crypto_guard.php'),
        ]);

        $this->app->bind('cryptoguard', function() {
            return new CryptoGuard(config('crypto_guard.passphrase'));
        });
    }

    public function boot()
    {

    }

}