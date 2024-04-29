<?php
class SyncTool
{
    const ALLOWED_CERT_FILE_EXTENSIONS = ['pem', 'crt'];

    /**
     * Take a server as parameter and return a HttpSocket object using the ssl options defined in the server settings
     * @param array|null $server
     * @param false $timeout
     * @param string $model
     * @return HttpSocketExtended
     * @throws Exception
     */
    public function setupHttpSocket($server = null, $timeout = false, $model = 'Server')
    {
        $params = ['compress' => true];
        if (!empty($server)) {
            if (!empty($server[$model]['cert_file'])) {
                $params['ssl_cafile'] = APP . "files" . DS . "certs" . DS . $server[$model]['cert_file'];
            }
            if (!empty($server[$model]['client_cert_file'])) {
                $params['ssl_local_cert'] = APP . "files" . DS . "certs" . DS . $server[$model]['client_cert_file'];
            }
            if (!empty($server[$model]['self_signed'])) {
                $params['ssl_allow_self_signed'] = true;
                $params['ssl_verify_peer_name'] = false;
                if (!isset($server[$model]['cert_file'])) {
                    $params['ssl_verify_peer'] = false;
                }
            }
            if (!empty($server[$model]['skip_proxy'])) {
                $params['skip_proxy'] = 1;
            }
            if (!empty($timeout)) {
                $params['timeout'] = $timeout;
            }
        }

        return $this->createHttpSocket($params);
    }

    public function setupHttpSocketFeed()
    {
        return $this->createHttpSocket(['compress' => true]);
    }

    /**
     * @param array $params
     * @return HttpSocketExtended
     * @throws Exception
     */
    public function createHttpSocket(array $params = [])
    {
        // Use own CA PEM file
        $caPath = Configure::read('MISP.ca_path');
        if (!isset($params['ssl_cafile']) && $caPath) {
            if (!file_exists($caPath)) {
                throw new Exception("CA file '$caPath' doesn't exists.");
            }
            $params['ssl_cafile'] = $caPath;
        }

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
                        throw new Exception("TLSv1.3 is not supported by PHP.");
                    }
                    break;
                default:
                    throw new InvalidArgumentException("Invalid `Security.min_tls_version` option $minTlsVersion");
            }
            $params['ssl_crypto_method'] = $version;
        }

        if (function_exists('curl_init')) {
            if (!isset($params['timeout']) && Configure::check('MISP.curl_request_timeout')) {
                $params['timeout'] = (int)Configure::read('MISP.curl_request_timeout');
            }
            App::uses('CurlClient', 'Tools');
            $HttpSocket = new CurlClient($params);
        } else {
            App::uses('HttpSocketExtended', 'Tools');
            $HttpSocket = new HttpSocketExtended($params);
        }

        $proxy = Configure::read('Proxy');
        if (empty($params['skip_proxy']) && isset($proxy['host']) && !empty($proxy['host'])) {
            $HttpSocket->configProxy($proxy['host'], $proxy['port'], $proxy['method'], $proxy['user'], $proxy['password']);
        }
        return $HttpSocket;
    }

    /**
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public static function getServerClientCertificateInfo(array $server)
    {
        if (!$server['Server']['client_cert_file']) {
            return;
        }

        $clientCertificate = new File(APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '_client.pem');
        if (!$clientCertificate->exists()) {
            throw new Exception("Certificate file '{$clientCertificate->pwd()}' doesn't exists.");
        }

        $certificateContent = $clientCertificate->read();
        if ($certificateContent === false) {
            throw new Exception("Could not read '{$clientCertificate->pwd()}' file with client certificate.");
        }

        return self::getClientCertificateInfo($certificateContent);
    }

    /**
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public static function getServerCaCertificateInfo(array $server)
    {
        if (!$server['Server']['cert_file']) {
            return;
        }

        $caCertificate = new File(APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '.pem');
        if (!$caCertificate->exists()) {
            throw new Exception("Certificate file '{$caCertificate->pwd()}' doesn't exists.");
        }

        $certificateContent = $caCertificate->read();
        if ($certificateContent === false) {
            throw new Exception("Could not read '{$caCertificate->pwd()}' file with certificate.");
        }

        $certificate = openssl_x509_read($certificateContent);
        if (!$certificate) {
            throw new Exception("Couldn't read certificate: " . openssl_error_string());
        }

        return self::parseCertificate($certificate);
    }

    /**
     * @param string $certificateContent PEM encoded certificate and private key.
     * @return array
     * @throws Exception
     */
    private static function getClientCertificateInfo($certificateContent)
    {
        $certificate = openssl_x509_read($certificateContent);
        if (!$certificate) {
            throw new Exception("Couldn't read certificate: " . openssl_error_string());
        }
        $privateKey = openssl_pkey_get_private($certificateContent);
        if (!$privateKey) {
            throw new Exception("Couldn't get private key from certificate: " . openssl_error_string());
        }
        $verify = openssl_x509_check_private_key($certificate, $privateKey);
        if (!$verify) {
            throw new Exception('Public and private key do not match.');
        }
        return self::parseCertificate($certificate);
    }

    /**
     * @param mixed $certificate
     * @return array
     * @throws Exception
     */
    private static function parseCertificate($certificate)
    {
        $parsed = openssl_x509_parse($certificate);
        if (!$parsed) {
            throw new Exception("Couldn't get parse X.509 certificate: " . openssl_error_string());
        }
        $currentTime = new DateTime();
        $output = [
            'serial_number' => $parsed['serialNumberHex'],
            'signature_type' => $parsed['signatureTypeSN'],
            'valid_from' => isset($parsed['validFrom_time_t']) ? new DateTime("@{$parsed['validFrom_time_t']}") : null,
            'valid_to' => isset($parsed['validTo_time_t']) ? new DateTime("@{$parsed['validTo_time_t']}") : null,
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
