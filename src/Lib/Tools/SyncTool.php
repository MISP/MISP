<?php

namespace App\Lib\Tools;

use Cake\Core\Configure;
use Cake\Http\Client as HttpSocket;

/**
 * @deprecated SyncTool - use HttpTool instead
 */
class SyncTool
{
    /**
     * @deprecated use $httpTool = new HttpTool(); $httpTool->configFromServer(array $server); instead
     * take a server as parameter and return a HttpSocket object using the ssl options defined in the server settings
     */
    public function setupHttpSocket($server = null, $timeout = false)
    {
        $params = [];
        if (!empty($server)) {
            if ($server['cert_file']) {
                $params['ssl_cafile'] = APP . "files" . DS . "certs" . DS . $server['id'] . '.pem';
            }
            if ($server['client_cert_file']) {
                $params['ssl_local_cert'] = APP . "files" . DS . "certs" . DS . $server['id'] . '_client.pem';
            }
            if ($server['self_signed']) {
                $params['ssl_allow_self_signed'] = true;
                $params['ssl_verify_peer_name'] = false;
                if (!isset($server['cert_file'])) {
                    $params['ssl_verify_peer'] = false;
                }
            }
            if (!empty($server['skip_proxy'])) {
                $params['skip_proxy'] = 1;
            }
            if (!empty($timeout)) {
                $params['timeout'] = $timeout;
            }
        }
        $httpTool = new HttpTool($params);
        $httpTool->configFromServer($server);
        return $httpTool;
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
    public function createHttpSocket($params = [])
    {
        $HttpSocket = new HttpSocket($params);
        $proxy = Configure::read('Proxy');
        if (empty($params['skip_proxy']) && isset($proxy['host']) && !empty($proxy['host'])) {
            $HttpSocket->configProxy($proxy['host'], $proxy['port'], $proxy['method'], $proxy['user'], $proxy['password']);
        }
        return $HttpSocket;
    }

    /**
     * @deprecated getServerClientCertificateInfo - use HttpTool::getServerClientCertificateInfo() instead
     * @param array $server
     * @return array|void
     * @throws Exception
     */
    public static function getServerClientCertificateInfo(array $server)
    {
        return HttpTool::getServerClientCertificateInfo($server);
    }

    /**
     * @deprecated - use HttpTool::getClientCertificateInfo() instead
     * @param string $certificateContent PEM encoded certificate and private key.
     * @return array
     * @throws Exception
     */
    private static function getClientCertificateInfo($certificateContent)
    {
        return HttpTool::getClientCertificateInfo($certificateContent);
    }

    /**
     * @deprecated - use HttpTool::parseCertificate() instead
     * @param mixed $certificate
     * @return array
     * @throws Exception
     */
    private static function parseCertificate($certificate)
    {
        return HttpTool::parseCertificate($certificate);
    }
}
