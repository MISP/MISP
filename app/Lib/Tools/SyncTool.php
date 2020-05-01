<?php

class SyncTool
{
    // take a server as parameter and return a HttpSocket object using the ssl options defined in the server settings
    public function setupHttpSocket($server = null, $timeout = false)
    {
        $params = array();
        if (!empty($server)) {
            if ($server['Server']['cert_file']) {
                $params['ssl_cafile'] = APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '.pem';
            }
            if ($server['Server']['client_cert_file']) {
                $params['ssl_local_cert'] = APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '_client.pem';
            }
            if ($server['Server']['self_signed']) {
                $params['ssl_allow_self_signed'] = true;
                $params['ssl_verify_peer_name'] = false;
                if (!isset($server['Server']['cert_file'])) {
                    $params['ssl_verify_peer'] = false;
                }
            }
            if (!empty($server['Server']['skip_proxy'])) {
                $params['skip_proxy'] = 1;
            }
            if (!empty($timeout)) {
                $params['timeout'] = $timeout;
            }
        }

        return $this->createHttpSocket($params);
    }

    public function setupHttpSocketFeed($feed = null)
    {
        return $this->setupHttpSocket();
    }

    /**
     * @param array $params
     * @return HttpSocket
     * @throws Exception
     */
    public function createHttpSocket($params = array())
    {
        // Use own CA PEM file
        $caPath = Configure::read('MISP.ca_path');
        if (!isset($params['ssl_cafile']) && $caPath) {
            if (!file_exists($caPath)) {
                throw new Exception("CA file '$caPath' doesn't exists.");
            }
            $params['ssl_cafile'] = $caPath;
        }

        App::uses('HttpSocket', 'Network/Http');
        $HttpSocket = new HttpSocket($params);
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
    public function getServerRemoteCertificateInfo(array $server)
    {
        $httpSocket = $this->setupHttpSocket($server, 5);
        // Disable all checks
        $httpSocket->config['ssl_verify_host'] = false;
        $httpSocket->config['ssl_allow_self_signed'] = true;
        $httpSocket->config['ssl_verify_peer'] = true;
        // Return peer cert in params
        $httpSocket->config['context']['ssl']['capture_peer_cert'] = true;

        // Keep alive to not close connection right after request
        $request = ['header' => ['Connection' => 'Keep-Alive']];
        try {
            $httpSocket->get($server['Server']['url'], false, $request);
        } catch (Exception $e) {
            return;
        }

        if (!$httpSocket->connected) {
            return;
        }

        $params = stream_context_get_params($httpSocket->connection);
        $certificateDetails = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        if (!$certificateDetails) {
            throw new Exception("Could't parse certificate: " . openssl_error_string());
        }
        return [
            'name' => $certificateDetails["name"],
            'serial_number' => $certificateDetails["serialNumber"],
            'valid_from' => new DateTime("@{$certificateDetails["validFrom_time_t"]}"),
            'valid_to' => new DateTime("@{$certificateDetails["validTo_time_t"]}"),
            'signature_type' => $certificateDetails["signatureTypeSN"],
        ];
    }

    /**
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public function getServerClientCertificateInfo(array $server)
    {
        if (!$server['Server']['client_cert_file']) {
            return;
        }

        $clientCertificate = new File(APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '_client.pem');
        if (!$clientCertificate->exists()) {
            throw new Exception("Certificate file doesn't exists");
        }

        $certificateContent = $clientCertificate->read();
        if ($certificateContent === false) {
            throw new Exception('Could not read file with client certificate: ' . $clientCertificate->pwd());
        }

        return $this->getClientCertificateInfo($certificateContent);
    }

    /**
     * @param string $certificateContent PEM encoded certificate and private key.
     * @return array
     * @throws Exception
     */
    private function getClientCertificateInfo($certificateContent)
    {
        $certificate = openssl_x509_read($certificateContent);
        if (!$certificate) {
            throw new Exception("Could't parse certificate: " . openssl_error_string());
        }
        $certificateDetails = openssl_x509_parse($certificate);
        if (!$certificateDetails) {
            throw new Exception("Could't get certificate details: " . openssl_error_string());
        }
        $privateKey = openssl_pkey_get_private($certificateContent);
        if (!$privateKey) {
            throw new Exception("Could't parse private key: " . openssl_error_string());
        }
        $verify = openssl_x509_check_private_key($certificate, $privateKey);
        if (!$verify) {
            throw new Exception("Public and private key do not match.");
        }
        return [
            'name' => $certificateDetails["name"],
            'serial_number' => $certificateDetails["serialNumber"],
            'valid_from' => new DateTime("@{$certificateDetails["validFrom_time_t"]}"),
            'valid_to' => new DateTime("@{$certificateDetails["validTo_time_t"]}"),
            'signature_type' => $certificateDetails["signatureTypeSN"],
        ];
    }
}
