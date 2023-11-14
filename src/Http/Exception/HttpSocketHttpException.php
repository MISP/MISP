<?php

namespace App\Http\Exception;

use Cake\Http\Client\Response;
use Exception;

class HttpSocketHttpException extends Exception
{
    /** @var Response */
    private $response;

    /** @var string|null */
    private $url;

    /**
     * @param Response $response
     * @param string|null $url
     */
    public function __construct(Response $response, $url = null)
    {
        $this->response = $response;
        $this->url = $url;
        $message = sprintf("Remote server returns HTTP error code %s", $response->getStatusCode());
        if ($url) {
            $message .= " for URL $url";
        }
        parent::__construct($message, (int)$response->getStatusCode());
    }

    /**
     * @return Response
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * Request URL
     * @return string|null
     */
    public function getUrl()
    {
        return $this->url;
    }
}
