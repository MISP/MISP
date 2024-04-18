<?php
App::uses('HttpSocketExtended', 'Tools');

class CurlClient extends HttpSocketExtended
{
    /** @var resource */
    private $ch;

    /**
     * Maximum time the transfer is allowed to complete in seconds
     * 300 seconds is recommended timeout for MISP servers
     * @var int
     */
    private $timeout = 300;

    /** @var string|null */
    private $caFile;

    /** @var string|null */
    private $localCert;

    /** @var int */
    private $cryptoMethod;

    /** @var bool */
    private $allowSelfSigned;

    /** @var bool */
    private $verifyPeer;

    /** @var bool */
    private $compress = true;

    /** @var array */
    private $proxy = [];

    /** @var array */
    private $defaultOptions;

    /**
     * @param array $params
     * @noinspection PhpMissingParentConstructorInspection
     */
    public function __construct(array $params)
    {
        if (isset($params['timeout'])) {
            $this->timeout = $params['timeout'];
        }
        if (isset($params['ssl_cafile'])) {
            $this->caFile = $params['ssl_cafile'];
        }
        if (isset($params['ssl_local_cert'])) {
            $this->localCert = $params['ssl_local_cert'];
        }
        if (isset($params['compress'])) {
            $this->compress = $params['compress'];
        }
        if (isset($params['ssl_crypto_method'])) {
            $this->cryptoMethod = $this->convertCryptoMethod($params['ssl_crypto_method']);
        }
        if (isset($params['ssl_allow_self_signed'])) {
            $this->allowSelfSigned = $params['ssl_allow_self_signed'];
        }
        if (isset($params['ssl_verify_peer'])) {
            $this->verifyPeer = $params['ssl_verify_peer'];
        }
        $this->defaultOptions = $this->generateDefaultOptions();
    }

    /**
     * @param string $uri
     * @param array $query
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function head($uri = null, $query = [], $request = [])
    {
        return $this->internalRequest('HEAD', $uri, $query, $request);
    }

    /**
     * @param string $uri
     * @param array $query
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function get($uri = null, $query = [], $request = [])
    {
        return $this->internalRequest('GET', $uri, $query, $request);
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function post($uri = null, $data = [], $request = [])
    {
        return $this->internalRequest('POST', $uri, $data, $request);
    }

    /**
     * @param string $uri
     * @param array$data
     * @param $request
     * @return HttpSocketResponseExtended
     */
    public function put($uri = null, $data = [], $request = [])
    {
        return $this->internalRequest('PUT', $uri, $data, $request);
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function patch($uri = null, $data = [], $request = [])
    {
        return $this->internalRequest('PATCH', $uri, $data, $request);
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    public function delete($uri = null, $data = array(), $request = array())
    {
        return $this->internalRequest('DELETE', $uri, $data, $request);
    }

    public function url($url = null, $uriTemplate = null)
    {
        throw new Exception('Not implemented');
    }

    public function request($request = array())
    {
        throw new Exception('Not implemented');
    }

    public function setContentResource($resource)
    {
        throw new Exception('Not implemented');
    }

    public function getMetaData()
    {
        return null; // not supported by curl extension
    }

    /**
     * @param string $host
     * @param int $port
     * @param string $method
     * @param string $user
     * @param string $pass
     * @return void
     */
    public function configProxy($host, $port = 3128, $method = null, $user = null, $pass = null)
    {
        if (empty($host)) {
            $this->proxy = [];
            return;
        }
        if (is_array($host)) {
            $this->proxy = $host + ['host' => null];
            return;
        }
        $this->proxy = compact('host', 'port', 'method', 'user', 'pass');
        $this->defaultOptions = $this->generateDefaultOptions(); // regenerate default options in case proxy setting is changed
    }

    /**
     * @param string $method
     * @param string $url
     * @param array|string $query
     * @param array $request
     * @return HttpSocketResponseExtended
     */
    private function internalRequest($method, $url, $query, $request)
    {
        if (empty($url)) {
            throw new InvalidArgumentException("No URL provided.");
        }

        if (!$this->ch) {
            // Share handle between requests to allow keep connection alive between requests
            $this->ch = curl_init();
            if (!$this->ch) {
                throw new \RuntimeException("Could not initialize curl");
            }
        } else {
            // Reset options, so we can do another request
            curl_reset($this->ch);
        }

        if (($method === 'GET' || $method === 'HEAD') && !empty($query)) {
            $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }

        $options = $this->defaultOptions; // this will copy default options
        $options[CURLOPT_URL] = $url;
        $options[CURLOPT_CUSTOMREQUEST] = $method;

        if (($method === 'POST' || $method === 'DELETE' || $method === 'PUT' || $method === 'PATCH') && !empty($query)) {
            $options[CURLOPT_POSTFIELDS] = $query;
        }

        if ($method === 'HEAD') {
            $options[CURLOPT_NOBODY] = true;
        }

        if (!empty($request['header'])) {
            $headers = [];
            foreach ($request['header'] as $key => $value) {
                if (is_array($value)) {
                    $value = implode(', ', $value);
                }
                $headers[] = "$key: $value";
            }
            $options[CURLOPT_HTTPHEADER] = $headers;
        }

        // Parse response headers
        $responseHeaders = [];
        $options[CURLOPT_HEADERFUNCTION] = function ($curl, $header) use (&$responseHeaders){
            $len = strlen($header);
            $header = explode(':', $header, 2);
            if (count($header) < 2) { // ignore invalid headers
                return $len;
            }
            $key = strtolower(trim($header[0]));
            $value = trim($header[1]);

            if (isset($responseHeaders[$key])) {
                $responseHeaders[$key] = array_merge((array)$responseHeaders[$key], [$value]);
            } else {
                $responseHeaders[$key] = $value;
            }
            return $len;
        };
        if (!curl_setopt_array($this->ch, $options)) {
            throw new \RuntimeException('curl error: Could not set options');
        }

        // Download the given URL, and return output
        $output = curl_exec($this->ch);

        if ($output === false) {
            $errorCode = curl_errno($this->ch);
            $errorMessage = curl_error($this->ch);
            if (!empty($errorMessage)) {
                $errorMessage = ": $errorMessage";
            }
            throw new SocketException("curl error $errorCode '" . curl_strerror($errorCode) . "'" . $errorMessage);
        }

        $code = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
        return $this->constructResponse($output, $responseHeaders, $code);
    }

    public function disconnect()
    {
        if ($this->ch) {
            curl_close($this->ch);
            $this->ch = null;
        }
    }

    /**
     * @param string $body
     * @param array $headers
     * @param int $code
     * @return HttpSocketResponseExtended
     */
    private function constructResponse($body, array $headers, $code)
    {
        $response = new HttpSocketResponseExtended();
        $response->code = $code;
        $response->body = $body;
        $response->headers = $headers;
        return $response;
    }

    /**
     * @param int $cryptoMethod
     * @return int
     */
    private function convertCryptoMethod($cryptoMethod)
    {
        switch ($cryptoMethod) {
            case STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT:
                return CURL_SSLVERSION_TLSv1;
            case STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT:
                return CURL_SSLVERSION_TLSv1_1;
            case STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT:
                return CURL_SSLVERSION_TLSv1_2;
            case STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT:
                return CURL_SSLVERSION_TLSv1_3;
            default:
                throw new InvalidArgumentException("Unsupported crypto method value $cryptoMethod");
        }
    }

    /**
     * @return array
     */
    private function generateDefaultOptions()
    {
        $options = [
            CURLOPT_FOLLOWLOCATION => true, // Allows to follow redirect
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_RETURNTRANSFER => true, // Should cURL return or print out the data? (true = return, false = print)
            CURLOPT_HEADER => false, // Include header in result?
            CURLOPT_TIMEOUT => $this->timeout, // Timeout in seconds
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP, // be sure that only HTTP and HTTPS protocols are enabled
        ];

        if ($this->caFile) {
            $options[CURLOPT_CAINFO] = $this->caFile;
        }

        if ($this->localCert) {
            $options[CURLOPT_SSLCERT] = $this->localCert;
        }

        if ($this->cryptoMethod) {
            $options[CURLOPT_SSLVERSION] = $this->cryptoMethod;
        }

        if ($this->compress) {
            $options[CURLOPT_ACCEPT_ENCODING] = ''; // empty string means all encodings supported by curl
        }

        if ($this->allowSelfSigned) {
            $options[CURLOPT_SSL_VERIFYPEER] = $this->verifyPeer;
            $options[CURLOPT_SSL_VERIFYHOST] = 0;
        }

        if (!empty($this->proxy)) {
            $options[CURLOPT_PROXY] = "{$this->proxy['host']}:{$this->proxy['port']}";
            if (!empty($this->proxy['method']) && isset($this->proxy['user'], $this->proxy['pass'])) {
                $options[CURLOPT_PROXYUSERPWD] = "{$this->proxy['user']}:{$this->proxy['pass']}";
            }
        }

        return $options;
    }
}