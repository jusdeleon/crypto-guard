<?php namespace Coreproc\CryptoGuard;

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

    public function encrypt($plaintext)
    {
        $this->generateSalt();
        $this->generateIv();

        $this->generateKey($this->passphrase);

        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $plaintext, MCRYPT_MODE_CBC, $this->iv);

        $data_return = array();
        $data_return['iv'] = base64_encode($this->iv);
        $data_return['salt'] = base64_encode($this->salt);
        $data_return['ciphertext'] = base64_encode($ciphertext);

        return base64_encode(json_encode($data_return));
    }

    public function decrypt($data_enciphered)
    {
        $data_decoded = json_decode(base64_decode($data_enciphered), true);

        $this->setIv(base64_decode($data_decoded['iv']));
        $this->setSalt(base64_decode($data_decoded['salt']));
        $this->generateKey($this->passphrase);

        $ciphertext = base64_decode($data_decoded['ciphertext']);

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
        $this->key = $this->pbkdf2('sha256', $passphrase, $this->salt, $iterations, $length);
    }

    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    private function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower($algorithm);
        if ( ! in_array($algorithm, hash_algos(), true))
            trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
        if ($count <= 0 || $key_length <= 0)
            trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);

        if (function_exists("hash_pbkdf2")) {
            return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }

        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($key_length / $hash_length);

        $output = "";
        for ($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if ($raw_output)
            return substr($output, 0, $key_length);
        else
            return bin2hex(substr($output, 0, $key_length));
    }

}