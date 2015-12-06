<?php

if ( ! function_exists('hash_pbkdf2')) {

    /**
     * Generate a PBKDF2 key derivation of a supplied password
     *
     * This is a hash_pbkdf2() implementation for PHP versions 5.3 and 5.4.
     * @link http://www.php.net/manual/en/function.hash-pbkdf2.php
     *
     * @param string $algo
     * @param string $password
     * @param string $salt
     * @param int $iterations
     * @param int $length
     * @param bool $rawOutput
     *
     * @return string
     */
    function hash_pbkdf2($algo, $password, $salt, $iterations, $length = 0, $rawOutput = false)
    {
        // check for hashing algorithm
        if ( ! in_array(strtolower($algo), hash_algos())) {
            trigger_error(sprintf('%s(): Unknown hashing algorithm: %s', __FUNCTION__, $algo), E_USER_WARNING);
            return false;
        }

        // check for type of iterations and length
        foreach (array(4 => $iterations, 5 => $length) as $index => $value) {
            if ( ! is_numeric($value)) {
                trigger_error(sprintf('%s() expects parameter %d to be long, %s given', __FUNCTION__, $index, gettype($value)), E_USER_WARNING);
                return null;
            }
        }

        // check iterations
        $iterations = (int) $iterations;
        if ($iterations <= 0) {
            trigger_error(sprintf('%s(): Iterations must be a positive integer: %d', __FUNCTION__, $iterations), E_USER_WARNING);
            return false;
        }

        // check length
        $length = (int) $length;
        if ($length < 0) {
            trigger_error(sprintf('%s(): Iterations must be greater than or equal to 0: %d', __FUNCTION__, $length), E_USER_WARNING);
            return false;
        }

        // check salt
        if (strlen($salt) > PHP_INT_MAX - 4) {
            trigger_error(sprintf('%s(): Supplied salt is too long, max of INT_MAX - 4 bytes: %d supplied', __FUNCTION__, strlen($salt)), E_USER_WARNING);
            return false;
        }

        // initialize
        $derivedKey = '';
        $loops = 1;
        if ($length > 0) {
            $loops = (int) ceil($length / strlen(hash($algo, '', $rawOutput)));
        }

        // hash for each blocks
        for ($i = 1; $i <= $loops; $i++) {
            $digest = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $block = $digest;
            for ($j = 1; $j < $iterations; $j++) {
                $digest = hash_hmac($algo, $digest, $password, true);
                $block ^= $digest;
            }
            $derivedKey .= $block;
        }

        if ( ! $rawOutput) {
            $derivedKey = bin2hex($derivedKey);
        }

        if ($length > 0) {
            return substr($derivedKey, 0, $length);
        }

        return $derivedKey;
    }

}

if ( ! function_exists('hash_equals')) {

    /**
     * Timing attack safe string comparison
     *
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks; for instance, when testing crypt() password hashes.
     *
     * @param string $known_string The string of known length to compare against
     * @param string $user_string The user-supplied string
     * @return boolean Returns TRUE when the two strings are equal, FALSE otherwise.
     */
    function hash_equals($known_string, $user_string)
    {
        if (func_num_args() !== 2) {
            // handle wrong parameter count as the native implentation
            trigger_error('hash_equals() expects exactly 2 parameters, ' . func_num_args() . ' given', E_USER_WARNING);
            return null;
        }
        if (is_string($known_string) !== true) {
            trigger_error('hash_equals(): Expected known_string to be a string, ' . gettype($known_string) . ' given', E_USER_WARNING);
            return false;
        }
        $known_string_len = strlen($known_string);
        $user_string_type_error = 'hash_equals(): Expected user_string to be a string, ' . gettype($user_string) . ' given'; // prepare wrong type error message now to reduce the impact of string concatenation and the gettype call
        if (is_string($user_string) !== true) {
            trigger_error($user_string_type_error, E_USER_WARNING);
            // prevention of timing attacks might be still possible if we handle $user_string as a string of diffent length (the trigger_error() call increases the execution time a bit)
            $user_string_len = strlen($user_string);
            $user_string_len = $known_string_len + 1;
        } else {
            $user_string_len = $known_string_len + 1;
            $user_string_len = strlen($user_string);
        }
        if ($known_string_len !== $user_string_len) {
            $res = $known_string ^ $known_string; // use $known_string instead of $user_string to handle strings of diffrent length.
            $ret = 1; // set $ret to 1 to make sure false is returned
        } else {
            $res = $known_string ^ $user_string;
            $ret = 0;
        }
        for ($i = strlen($res) - 1; $i >= 0; $i--) {
            $ret |= ord($res[$i]);
        }
        return $ret === 0;
    }

}