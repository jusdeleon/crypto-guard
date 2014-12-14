CryptoGuard
========

A PHP library that gives a simple interface for encrypting and decrypting strings

## Quick start

### Required setup

The easiest way to install this library is via Composer.

Create a `composer.json` file and enter the following:

    {
        "require": {
            "coreproc/crypto-guard": "0.*"
        }
    }

If you haven't yet downloaded your composer file, you can do so by executing the following in your command line:

    curl -sS https://getcomposer.org/installer | php

Once you've downloaded the composer.phar file, continue with your installation by running the following:

    php composer.phar install

## Usage

### Basic Usage

    <?php
    
    require 'vendor/autoload.php';
    
    use Coreproc\CryptoGuard\CryptoGuard;
    
    // This passphrase should be consistent and will be used as your key to encrypt/decrypt
    // your string
    $passphrase = 'whatever-you-want';
    
    // Instantiate the CryptoGuard class
    $cryptoGuard = new CryptoGuard($passphrase);
    
    $stringToEncrypt = 'test';
    
    // This will spit out the encrypted text
    $encryptedText = $cryptoGuard->encrypt($stringToEncrypt);
    
    // This should give you back the string you encrypted
    echo $cryptoGuard->decrypt($encryptedText);
