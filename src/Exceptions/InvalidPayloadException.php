<?php

namespace Coreproc\CryptoGuard\Exceptions;

use Exception;

class InvalidPayloadException extends Exception
{

    public function __construct($message = 'Payload is invalid', $code = 400, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

}