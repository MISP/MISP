<?php

namespace App\Lib\Tools;

use App\Lib\Tools\CurlAdvanced;
use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;
use Cake\Http\Client as CakeClient;
use Cake\Http\Client\Request;
use Cake\Http\Client\Response;
use Cake\Http\Exception\NotImplementedException;
use Cake\I18n\FrozenTime;


class HttpTool extends CakeClient
{

    public function __construct(array $config = [])
    {
        $this->buildDefaultConfigFromSettings();

        // Custom Curl Adapter to give extra features, including SSL Cert dumping
        // $config['adapter'] = CurlAdvanced::class;

        parent::__construct($config);
    }

        
    /**
     * buildDefaultConfigFromSettings
     *
     * @return array
     */
    public function buildDefaultConfigFromSettings()
    {
        /*
        ## CakeClient settings
        headers - Array of additional headers
        cookie - Array of cookies to use.
        proxy - Array of proxy information.
        auth - Array of authentication data, the type key is used to delegate to an authentication strategy. By default Basic auth is used.
        ssl_verify_peer - defaults to true. Set to false to disable SSL certification verification (not recommended).
        ssl_verify_peer_name - defaults to true. Set to false to disable host name verification when verifying SSL certificates (not recommended).
        ssl_verify_depth - defaults to 5. Depth to traverse in the CA chain.
        ssl_verify_host - defaults to true. Validate the SSL certificate against the host name.
        ssl_cafile - defaults to built in cafile. Overwrite to use custom CA bundles.
        timeout - Duration to wait before timing out in seconds.
        type - Send a request body in a custom content type. Requires $data to either be a string, or the _content option to be set when doing GET requests.
        redirect - Number of redirects to follow. Defaults to false.
        curl - An array of additional curl options (if the curl adapter is used), for example, [CURLOPT_SSLKEY => 'key.pem'].
        
        ## MISP global settings
        MISP.ca_path - certificate store
        Proxy.host, port, user, pass, method
        Security.min_tls_version

        ## MISP server/cerebrate setting
        These settings are loaded in the _doRequest() function
        - cert_file - translates to 'ssl_cafile'
        - client_cert_file - translates to 'ssl_local_cert' - SSL client side authentication - see CURLOPT_SSLKEY
        - self_signed - translates to 'ssl_allow_self_signed', 'ssl_verify_peer_name', 'ssl_verify_peer'
        - skip_proxy - 
        */
        

        // proxy settings
        $proxy = Configure::read('Proxy');
        // proxy array as CakeClient likes it 
        // ['username' => 'mark',
        //  'password' => 'testing',
        //  'proxy' => '127.0.0.1:8080'] 

        if (isset($proxy['host'])) {
            $this->_defaultConfig['proxy'] = ['proxy' => $proxy['host'] . ":" . (empty($proxy['port']) ? 3128 : $proxy['port'])];
            
            if (isset($proxy['user']) && isset($proxy['password']) && !isset($proxy['method'])) {
                $proxy['method'] = 'basic';
            }
            if (isset($proxy['method'])) {
                if (strtolower($proxy['method']) == 'basic' && isset($proxy['user']) && isset($proxy['password'])) {
                    $this->_defaultConfig['proxy']['username'] = $proxy['user'];
                    $this->_defaultConfig['proxy']['password'] = $proxy['password'];
                }
                if (strtolower($proxy['method']) == 'digest') {
                    throw new NotImplementedException('Digest proxy auth is not implemented'); // FIXME chri support Digest proxy auth
                }
            }
        }

        // global Certificate Authority
        $caPath = Configure::read('MISP.ca_path');
        if ($caPath) {
            if (!file_exists($caPath)) {
                throw new CakeException("CA file '$caPath' doesn't exists.");
            }
            $this->_defaultConfig['ssl_cafile'] = $caPath;
        }

        // min TLS version
        if ($minTlsVersion = Configure::read('Security.min_tls_version')) {
            $version = 0;
            switch ($minTlsVersion) {
                case 'tlsv1_0':
                    $version |= STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT;
                case 'tlsv1_1':
                    $version |= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
                case 'tlsv1_2':
                    $version |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
                case 'tlsv1_3':
                    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                        $version |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
                    } else if ($minTlsVersion === 'tlsv1_3') {
                        throw new CakeException("TLSv1.3 is not supported by PHP.");
                    }
                    break;
                default:
                    throw new CakeException("Invalid `Security.min_tls_version` option $minTlsVersion");
            }
            $this->_defaultConfig['ssl_crypto_method'] = $version;
        }

        // Add user-agent
        $this->_defaultConfig['headers']['User-Agent'] = "MISP - Threat Intelligence & Sharing Platform"; // LATER add MISP version 
    }

    /**
     * Helper method for doing non-GET requests. This method is there to provide us a wrapper implementing our custom options.
     *
     * @param string $method HTTP method.
     * @param string $url URL to request.
     * @param mixed $data The request body.
     * @param array<string, mixed> $options The options to use. Contains auth, proxy, etc.
     * @return \Cake\Http\Client\Response
     */
    protected function _doRequest(string $method, string $url, $data, $options): Response
    {
        if (isset($options['self_signed']) && $options['self_signed'] === true) {
            $options = array_merge($options, [
                'ssl_verify_peer' => false,
                'ssl_verify_host' => false]);
        }
        if (isset($options['skip_proxy']) && $options['skip_proxy'] === true) {
            unset($options['proxy']); 
        }
        return parent::_doRequest($method, $url, $data, $options);
    }

    /**
     * @deprecated createRequest - return an instance of HttpTool with automatic configuration
     * @deprecated do not use this function, but use the HttpTool directly instead
     * @param  mixed $config
     * @return HttpTool
     */
    public function createRequest(array $config = []): HttpTool
    {
        return new HttpTool($config);
    }

        
    /**
     * fetchCertificate - download the SSL certificate from the remote server
     *
     * @return array the list of certificates including pem
     */
    public function fetchCertificates(string $url, array $options = []) : array
    {
        $options = $this->_mergeOptions($options);
        $options['ssl_verify_peer'] = false;
        $options['ssl_verify_host'] = false;
        $options['ssl_verify_peer_name'] = false;
        // set CURL options, this is the place where magic happens.
        $data = [];
        $url = $this->buildUrl($url, $data, $options);
        $request = $this->_createRequest(
            Request::METHOD_GET,
            $url,
            $data,
            $options
        );
        $curl = new CurlAdvanced();
        $certificates = $curl->getCertificateChain($request, $options);
        return $certificates;
    }

    /**
     * getServerClientCertificateInfo - extract certificate info from a Client certificate from a $server.
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public static function getServerClientCertificateInfo(array $server): mixed
    {
        if (!$server['client_cert_file']) {
            return null;
        }
        $fileAccessTool = new FileAccessTool();
        $path = APP . "files" . DS . "certs" . DS . $server['id'] . '_client.pem';
        $clientCertificate = $fileAccessTool->readFromFile($path); //readFromFile throws an exception if the file is not found or could not be read, along with the reason.

        return self::getClientCertificateInfo($clientCertificate);
    }

    /**
     * getServerCaCertificateInfo - extract certificate info from a certificate from a $server.
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public static function getServerCaCertificateInfo(array $server): mixed
    {
        if (!$server['Server']['cert_file']) {
            return null;
        }

        $fileAccessTool = new FileAccessTool();
        $path = APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '.pem';
        $caCertificate = $fileAccessTool->readFromFile($path); //readFromFile throws an exception if the file is not found or could not be read, along with the reason.
        $certificate = openssl_x509_read($caCertificate);
        if (!$certificate) {
            throw new CakeException("Couldn't read certificate: " . openssl_error_string());
        }

        return self::parseCertificate($certificate);
    }

    /**
     * getClientCertificateInfo - extract client certificate info from a PEM encoded cert + key, only if the cert+key are valid
     * @param string $certificateContent PEM encoded certificate and private key.
     * @return array
     * @throws Exception
     */
    private static function getClientCertificateInfo(string $certificateContent): array
    {
        $certificate = openssl_x509_read($certificateContent);
        if (!$certificate) {
            throw new CakeException("Couldn't read certificate: " . openssl_error_string());
        }
        $privateKey = openssl_pkey_get_private($certificateContent);
        if (!$privateKey) {
            throw new CakeException("Couldn't get private key from certificate: " . openssl_error_string());
        }
        $verify = openssl_x509_check_private_key($certificate, $privateKey);
        if (!$verify) {
            throw new CakeException('Public and private key do not match.');
        }
        return self::parseCertificate($certificate);
    }

    /**
     * parseCertificate - extract certificate info from a PEM encoded certificate
     * @param mixed $certificate
     * @return array
     * @throws Exception
     */
    public static function parseCertificate(mixed $certificate): array
    {
        /* @var $parsed array */
        $parsed = openssl_x509_parse($certificate);
        if (!$parsed) {
            throw new CakeException("Couldn't get parse X.509 certificate: " . openssl_error_string());
        }
        $currentTime = FrozenTime::now();
        $output = [
            'serial_number' => $parsed['serialNumberHex'],
            'signature_type' => $parsed['signatureTypeSN'],
            'valid_from' => isset($parsed['validFrom_time_t']) ? new FrozenTime("@{$parsed['validFrom_time_t']}") : null,
            'valid_to' => isset($parsed['validTo_time_t']) ? new FrozenTime("@{$parsed['validTo_time_t']}") : null,
            'public_key_size' => null,
            'public_key_type' => null,
            'public_key_size_ok' => null,
        ];

        $output['valid_from_ok'] = $output['valid_from'] ? ($output['valid_from'] <= $currentTime) : null;
        $output['valid_to_ok'] = $output['valid_to'] ? ($output['valid_to'] >= $currentTime) : null;

        $subject = [];
        foreach ($parsed['subject'] as $type => $value) {
            $subject[] = "$type=$value";
        }
        $output['subject'] = implode(', ', $subject);

        $issuer = [];
        foreach ($parsed['issuer'] as $type => $value) {
            $issuer[] = "$type=$value";
        }
        $output['issuer'] = implode(', ', $issuer);

        $publicKey = openssl_pkey_get_public($certificate);
        if ($publicKey) {
            $publicKeyDetails = openssl_pkey_get_details($publicKey);
            if ($publicKeyDetails) {
                $output['public_key_size'] = $publicKeyDetails['bits'];
                switch ($publicKeyDetails['type']) {
                    case OPENSSL_KEYTYPE_RSA:
                        $output['public_key_type'] = 'RSA';
                        $output['public_key_size_ok'] = $output['public_key_size'] >= 2048;
                        break;
                    case OPENSSL_KEYTYPE_DSA:
                        $output['public_key_type'] = 'DSA';
                        $output['public_key_size_ok'] = $output['public_key_size'] >= 2048;
                        break;
                    case OPENSSL_KEYTYPE_DH:
                        $output['public_key_type'] = 'DH';
                        break;
                    case OPENSSL_KEYTYPE_EC:
                        $output['public_key_type'] = "EC ({$publicKeyDetails['ec']['curve_name']})";
                        $output['public_key_size_ok'] = $output['public_key_size'] >= 224;
                        break;
                }
            }
        }

        return $output;
    }
}
