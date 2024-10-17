<?php
App::uses('HttpSocketResponse', 'Network/Http');
App::uses('HttpSocket', 'Network/Http');

class HttpSocketHttpException extends Exception
{
    /** @var HttpSocketResponseExtended */
    private $response;

    /** @var string|null */
    private $url;

    /**
     * @param HttpSocketResponseExtended $response
     * @param string|null $url
     */
    public function __construct(HttpSocketResponseExtended $response, $url = null)
    {
        $this->response = $response;
        $this->url = $url;

        $message = "Remote server returns HTTP error code $response->code";
        if ($url) {
            $message .= " for URL $url";
        }
        if ($response->body) {
            $message .= ': ' . substr(ltrim($response->body), 0, 100);
        }

        parent::__construct($message, (int)$response->code);
    }

    /**
     * @return HttpSocketResponseExtended
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

class HttpSocketJsonException extends Exception
{
    /** @var HttpSocketResponseExtended */
    private $response;

    public function __construct($message, HttpSocketResponseExtended $response, Throwable $previous = null)
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

class HttpSocketResponseExtended extends HttpSocketResponse
{
    /**
     * @return bool
     */
    public function isNotModified()
    {
        return $this->code == 304;
    }

    /**
     * @param string $message
     * @throws SocketException
     */
    public function parseResponse($message)
    {
        parent::parseResponse($message);

        if ($this->body === '') {
            return; // skip decoding body if is empty
        }

        $contentEncoding = $this->getHeader('Content-Encoding');
        if ($contentEncoding === 'gzip' && function_exists('gzdecode')) {
            $this->body = gzdecode($this->body);
            if ($this->body === false) {
                throw new SocketException("Response should be gzip encoded, but gzip decoding failed.");
            }
        } else if ($contentEncoding === 'br' && function_exists('brotli_uncompress')) {
            $this->body = brotli_uncompress($this->body);
            if ($this->body === false) {
                throw new SocketException("Response should be brotli encoded, but brotli decoding failed.");
            }
        } else if ($contentEncoding) {
            throw new SocketException("Remote server returns unsupported content encoding '$contentEncoding'.");
        }
    }

    /**
     * Decodes JSON string and throws exception if string is not valid JSON.
     *
     * @return array
     * @throws HttpSocketJsonException
     */
    public function json()
    {
        if (strlen($this->body) === 0) {
            throw new HttpSocketJsonException('Could not parse empty response as JSON.', $this);
        }

        try {
            return JsonTool::decode($this->body);
        } catch (Exception $e) {
            $contentType = $this->getHeader('content-type');
            throw new HttpSocketJsonException("Could not parse HTTP response as JSON. Received Content-Type $contentType.", $this, $e);
        }
    }
}

/**
 * Supports response compression and also decodes response as JSON
 * @method HttpSocketResponseExtended get($uri = null, $query = array(), $request = array())
 * @method HttpSocketResponseExtended post($uri = null, $data = array(), $request = array())
 * @method HttpSocketResponseExtended head($uri = null, $query = array(), $request = array())
 */
class HttpSocketExtended extends HttpSocket
{
    public $responseClass = 'HttpSocketResponseExtended';

    /** @var callable */
    private $onConnect;

    public function __construct($config = array())
    {
        parent::__construct($config);
        if (isset($config['compress']) && $config['compress']) {
            $acceptEncoding = $this->acceptedEncodings();
            if (!empty($acceptEncoding)) {
                $this->config['request']['header']['Accept-Encoding'] = implode(', ', $this->acceptedEncodings());
            }
        }
    }

    public function connect()
    {
        $connected = parent::connect();
        if ($this->onConnect) {
            $handler = $this->onConnect;
            $handler($this);
        }
        return $connected;
    }

    /**
     * Set callback method, that will be called after connection to remote server is established.
     * @param callable $callback
     * @return void
     */
    public function onConnectHandler(callable $callback)
    {
        $this->onConnect = $callback;
    }

    /**
     * @return array|null
     */
    public function getMetaData()
    {
        if ($this->connection) {
            return stream_get_meta_data($this->connection);
        }
        return null;
    }

    /**
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function request($request = array())
    {
        // Reset last error
        $this->lastError = [];

        /** @var HttpSocketResponseExtended $response */
        $response = parent::request($request);
        if ($response === false) {
            throw new InvalidArgumentException("Invalid argument provided.");
        }
        // Convert connection timeout to SocketException
        if (!empty($this->lastError)) {
            throw new SocketException($this->lastError['str']);
        }
        return $response;
    }

    /**
     * Returns accepted content encodings (compression algorithms)
     * @return string[]
     */
    private function acceptedEncodings()
    {
        $supportedEncoding = [];
        // Enable brotli compressed responses if PHP has 'brotli_uncompress' method
        if (function_exists('brotli_uncompress')) {
            $supportedEncoding[] = 'br';
        }
        // Enable gzipped responses if PHP has 'gzdecode' method
        if (function_exists('gzdecode')) {
            $supportedEncoding[] = 'gzip';
        }
        return $supportedEncoding;
    }
}
