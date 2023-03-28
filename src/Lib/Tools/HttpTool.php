<?php
namespace App\Lib\Tools;

use Cake\Core\Exception\Exception;
use Cake\Core\Configure;
use Cake\Http\Client;
use Cake\I18n\FrozenTime;

class HttpTool
{
    
    public function createRequest(array $params = []): Client
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
                    throw new Exception("Invalid `Security.min_tls_version` option $minTlsVersion");
            }
            $params['ssl_crypto_method'] = $version;
        }
        //require_once(ROOT . '/src/Lib/Tools/HttpSocketExtended.php');
        //$HttpSocket = new HttpSocketExtended($params);
        // $client = new Client();
        $proxy = Configure::read('Proxy');
        if (empty($params['skip_proxy']) && isset($proxy['host']) && !empty($proxy['host'])) {
            $params['proxy'] = [
                'username' => $proxy['user'],
                'password' => $proxy['password'],
                'proxy' => $proxy['host'] . (empty($proxy['port']) ? '' : ':' . $proxy['port'])
            ];
        }
        return new Client($params);
    }

    /**
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
            throw new Exception("Couldn't read certificate: " . openssl_error_string());
        }

        return self::parseCertificate($certificate);
    }

    /**
     * @param string $certificateContent PEM encoded certificate and private key.
     * @return array
     * @throws Exception
     */
    private static function getClientCertificateInfo(string $certificateContent): array
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
    private static function parseCertificate(mixed $certificate): array
    {
        $parsed = openssl_x509_parse($certificate);
        if (!$parsed) {
            throw new Exception("Couldn't get parse X.509 certificate: " . openssl_error_string());
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
