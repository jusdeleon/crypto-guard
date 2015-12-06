<?php

namespace Coreproc\CryptoGuard;

use Coreproc\CryptoGuard\Exceptions\InvalidPayloadException;
use Exception;

class CryptoGuard
{

    private $passphrase;
    private $key;
    private $salt;
    private $iv;

    public function __construct($passphrase)
    {
        $this->passphrase = $passphrase;
    }

    /**
     * Encrypt a string
     *
     * @param string $plaintext
     * @return string
     */
    public function encrypt($plaintext)
    {
        $this->generateSalt();
        $this->generateIv();

        $this->generateKey($this->passphrase);

        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $plaintext, MCRYPT_MODE_CBC, $this->iv);

        $dataReturn = array();
        $dataReturn['iv'] = base64_encode($this->iv);
        $dataReturn['salt'] = base64_encode($this->salt);
        $dataReturn['ciphertext'] = base64_encode($ciphertext);
        $dataReturn['sig'] = base64_encode($this->hmacSign($ciphertext, $this->iv));

        return base64_encode(json_encode($dataReturn));
    }

    /**
     * Decrypt the encrypted string
     *
     * @param $dataEnciphered
     * @return string
     * @throws Exception
     */
    public function decrypt($dataEnciphered)
    {
        $dataDecoded = json_decode(base64_decode($dataEnciphered), true);

        $this->setIv(base64_decode($dataDecoded['iv']));
        $this->setSalt(base64_decode($dataDecoded['salt']));
        $this->generateKey($this->passphrase);

        $ciphertext = base64_decode($dataDecoded['ciphertext']);

        $originalSignature = base64_decode($dataDecoded['sig']);

        // Attempt to verify signature
        if ($this->hmacVerify($originalSignature, $this->iv) == false) {
            throw new InvalidPayloadException();
        }

        return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, $ciphertext, MCRYPT_MODE_CBC, $this->iv));
    }

    private function setSalt($salt)
    {
        $this->salt = $salt;
    }

    private function generateSalt()
    {
        $this->salt = mcrypt_create_iv(32, MCRYPT_DEV_RANDOM); // abuse IV function for random salt
    }

    private function setIv($iv)
    {
        $this->iv = $iv;
    }

    private function generateIv()
    {
        $this->iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC));
    }

    private function generateKey($passphrase, $iterations = 10000, $length = 32)
    {
        $this->key = hash_pbkdf2('sha256', $passphrase, $this->salt, $iterations, $length);
    }

    private function hmacSign($ciphertext, $key)
    {
        return hash_hmac('sha256', $ciphertext, $key) . $ciphertext;
    }

    /**
     * @param $bundle
     * @param $key
     * @return bool
     */
    private function hmacVerify($bundle, $key)
    {
        $msgMAC = mb_substr($bundle, 0, 64, '8bit');
        $message = mb_substr($bundle, 64, null, '8bit');
        return hash_equals(
            hash_hmac('sha256', $message, $key),
            $msgMAC
        );
    }

}