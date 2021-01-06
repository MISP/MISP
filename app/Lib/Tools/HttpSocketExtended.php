<?php
App::uses('HttpSocketResponse', 'Network/Http');
App::uses('HttpSocket', 'Network/Http');

class HttpClientJsonException extends Exception
{
    /** @var HttpSocketResponse */
    private $response;

    public function __construct($message, HttpSocketResponseExtended $response, Throwable $previous = null)
    {
        $this->response = $response;
        parent::__construct($message, 0, $previous);
    }

    /**
     * @return HttpSocketResponse
     */
    public function getResponse()
    {
        return $this->response;
    }
}

class HttpSocketResponseExtended extends HttpSocketResponse
{
    /**
     * @param string $message
     * @throws SocketException
     */
    public function parseResponse($message)
    {
        parent::parseResponse($message);

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
            throw new SocketException("Remote server returns unsupported content encoding '$contentEncoding'");
        }
    }

    /**
     * Decodes JSON string and throws exception if string is not valid JSON.
     *
     * @return array
     * @throws HttpClientJsonException
     */
    public function json()
    {
        try {
            if (defined('JSON_THROW_ON_ERROR')) {
                // JSON_THROW_ON_ERROR is supported since PHP 7.3
                $decoded = json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
            } else {
                $decoded = json_decode($this->body, true);
                if ($decoded === null) {
                    throw new UnexpectedValueException('Could not parse JSON: ' . json_last_error_msg(), json_last_error());
                }
            }
            return $decoded;
        } catch (Exception $e) {
            throw new HttpClientJsonException('Could not parse response as JSON.', $this, $e);
        }
    }
}

/**
 * Supports response compression and also decodes response as JSON
 */
class HttpSocketExtended extends HttpSocket
{
    public $responseClass = 'HttpSocketResponseExtended';

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
            throw new SocketException($this->lastError['msg']);
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
