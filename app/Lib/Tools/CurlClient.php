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
    private $verifyPeer = true;

    /** @var bool */
    private $compress = true;

    /** @var array */
    private $proxy = [];

    /**
     * CURLOPT_RESOLVE entries, as "host:port:ip". Lets a caller that has
     * already validated where a name points force the connection to that
     * exact address, closing the window in which the name could resolve
     * somewhere else between the check and the request.
     * @var array
     */
    private $pinnedHosts = [];

    /** @var bool */
    private $followRedirects = true;

    /** @var int|null Maximum response body size in bytes, null for no limit */
    private $maxSize;

    /**
     * Called as ($fromUrl, $toUrl, $client) before each redirect is taken.
     * Returning false or throwing refuses the hop. When set, curl's own
     * following is turned off and redirects are driven here instead, because
     * curl resolves a redirect target fresh and a pin on the original host
     * does not constrain it.
     * @var callable|null
     */
    private $redirectValidator;

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
     * Force connections to $host:$port to use $ip.
     *
     * Only meaningful for a name - curl does not resolve an address literal,
     * so there is no lookup to override. Pass the address that was actually
     * validated: without this, a validated hostname is resolved again at
     * request time and may answer differently.
     *
     * @param string $host
     * @param int $port
     * @param string $ip
     * @return void
     */
    public function pinHost($host, $port, $ip)
    {
        if (str_contains($ip, ':')) {
            $ip = "[$ip]"; // curl wants IPv6 addresses bracketed here
        }
        $this->pinnedHosts[] = sprintf('%s:%d:%s', $host, $port, $ip);
        $this->defaultOptions = $this->generateDefaultOptions();
    }

    /**
     * Whether curl follows redirects itself. Turn this off when each hop has
     * to be validated before it is taken - curl resolves a redirect target
     * fresh, so a pin on the original host does not constrain it.
     *
     * @param bool $follow
     * @return void
     */
    public function setFollowRedirects($follow)
    {
        $this->followRedirects = (bool)$follow;
        $this->defaultOptions = $this->generateDefaultOptions();
    }

    /**
     * Abort a response larger than $bytes.
     *
     * Enforced twice: CURLOPT_MAXFILESIZE rejects an honestly advertised
     * Content-Length before any body is transferred, and the progress
     * callback catches a server that understates or omits it.
     *
     * @param int|null $bytes null removes the limit
     * @return void
     */
    public function setMaxSize($bytes)
    {
        $this->maxSize = $bytes === null ? null : (int)$bytes;
        $this->defaultOptions = $this->generateDefaultOptions();
    }

    /**
     * Vet every redirect before it is taken, instead of letting curl follow
     * them unseen.
     *
     * The callable receives ($fromUrl, $toUrl, $client) and refuses the hop by
     * returning false or throwing. It is handed the client so it can pin the
     * new host to an address it has just validated. Only GET and HEAD are
     * followed; anything else stops at the redirect and returns it.
     *
     * @param callable|null $validator null restores curl's own following
     * @return void
     */
    public function setRedirectValidator($validator = null)
    {
        if ($validator !== null && !is_callable($validator)) {
            throw new InvalidArgumentException('Redirect validator must be callable.');
        }
        $this->redirectValidator = $validator;
        $this->setFollowRedirects($validator === null);
    }

    /**
     * @param string $method
     * @param string $url
     * @param array|string $query
     * @param array $request
     * @param int $redirectsFollowed
     * @return HttpSocketResponseExtended
     */
    private function internalRequest($method, $url, $query, $request, $redirectsFollowed = 0)
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
            // Both of these mean the size limit tripped: 63 when the server
            // advertised too large a Content-Length, 42 when the progress
            // callback aborted a body that grew past the limit anyway.
            if ($this->maxSize !== null && ($errorCode === CURLE_FILESIZE_EXCEEDED || $errorCode === CURLE_ABORTED_BY_CALLBACK)) {
                throw new SocketException("Response exceeds the maximum allowed size of {$this->maxSize} bytes.");
            }
            $errorMessage = curl_error($this->ch);
            if (!empty($errorMessage)) {
                $errorMessage = ": $errorMessage";
            }
            throw new SocketException("curl error $errorCode '" . curl_strerror($errorCode) . "'" . $errorMessage);
        }

        $code = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);

        // Try to release pointer to local function to avoid circular reference and releasing memory
        // See https://github.com/php-mod/curl/issues/95
        curl_reset($this->ch);

        if ($this->redirectValidator !== null && ($method === 'GET' || $method === 'HEAD')) {
            $target = $this->redirectTarget($code, $responseHeaders, $url);
            if ($target !== null) {
                if ($redirectsFollowed >= 10) {
                    throw new SocketException("Too many redirects while fetching $url.");
                }
                if (call_user_func($this->redirectValidator, $url, $target, $this) === false) {
                    throw new SocketException("Refused to follow the redirect from $url to $target.");
                }
                // The Location already carries its own query string, so the
                // original query must not be appended a second time.
                return $this->internalRequest($method, $target, [], $request, $redirectsFollowed + 1);
            }
        }

        return $this->constructResponse($output, $responseHeaders, $code);
    }

    /**
     * @param int $code
     * @param array $responseHeaders
     * @param string $currentUrl
     * @return string|null absolute redirect target, or null if not a redirect
     */
    private function redirectTarget($code, array $responseHeaders, $currentUrl)
    {
        if (!in_array((int)$code, [301, 302, 303, 307, 308], true)) {
            return null;
        }
        $location = isset($responseHeaders['location']) ? $responseHeaders['location'] : null;
        if (is_array($location)) {
            $location = end($location);
        }
        if (empty($location)) {
            return null;
        }
        App::uses('UrlEgressValidator', 'Tools');
        return UrlEgressValidator::resolveLocation($location, $currentUrl);
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
            CURLOPT_FOLLOWLOCATION => $this->followRedirects, // Allows to follow redirect
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

        if (!empty($this->pinnedHosts)) {
            $options[CURLOPT_RESOLVE] = $this->pinnedHosts;
        }

        if ($this->maxSize !== null) {
            $maxSize = $this->maxSize;
            $options[CURLOPT_MAXFILESIZE] = $maxSize;
            $options[CURLOPT_NOPROGRESS] = false;
            $options[CURLOPT_PROGRESSFUNCTION] = function ($curl, $downloadSize, $downloaded, $uploadSize, $uploaded) use ($maxSize) {
                // Non-zero aborts the transfer. Checking the advertised size
                // too stops a large body before the first byte arrives.
                return ($downloaded > $maxSize || $downloadSize > $maxSize) ? 1 : 0;
            };
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