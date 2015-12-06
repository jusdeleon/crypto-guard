<?php

class CryptoGuardTest extends PHPUnit_Framework_TestCase
{

    public function testEncryption()
    {
        require_once __DIR__ . '/../vendor/autoload.php';

        $passphrase = 'test-passphrase';

        $cryptoGuard = new \Coreproc\CryptoGuard\CryptoGuard($passphrase);

        $stringToEncrypt = 'test string to encrypt';

        $encryptedText = $cryptoGuard->encrypt($stringToEncrypt);

        $decryptedText = $cryptoGuard->decrypt($encryptedText);

        $this->assertEquals($stringToEncrypt, $decryptedText);
    }

    /**
     * @expectedException Coreproc\CryptoGuard\Exceptions\InvalidPayloadException
     */
    public function testFailedDecryption()
    {
        require_once __DIR__ . '/../vendor/autoload.php';

        $passphrase = 'test-passphrase';

        $cryptoGuard = new \Coreproc\CryptoGuard\CryptoGuard($passphrase);

        $stringToEncrypt = 'test string to encrypt';

        $encryptedText = $cryptoGuard->encrypt($stringToEncrypt);

        // decrypt the string
        $decryptedText = json_decode(base64_decode($encryptedText), true);

        $decryptedText['iv'] = 'changed-iv-for-test';

        // encrypt again
        $encryptedText = base64_encode(json_encode($decryptedText));

        $decryptedText = $cryptoGuard->decrypt($encryptedText);
    }

}