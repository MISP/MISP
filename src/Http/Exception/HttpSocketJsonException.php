<?php

namespace App\Http\Exception;

use Exception;
use Cake\Http\Client\Response;
use Throwable;

class HttpSocketJsonException extends Exception
{
    /** @var HttpSocketResponseExtended */
    private $response;

    public function __construct($message, Response $response, Throwable $previous = null)
    {
        $this->response = $response;
        parent::__construct($message, 0, $previous);
    }

    /**
     * @return HttpSocketResponseExtended
     */
    public function getResponse()
    {
        return $this->response;
    }
}
