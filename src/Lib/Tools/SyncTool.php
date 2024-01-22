<?php

namespace App\Lib\Tools;

use App\Lib\Tools\HttpTool;
use Cake\I18n\FrozenTime;
use Exception;

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
        $config = [];
        if (!empty($timeout)) {
            $config['timeout'] = $timeout;
        }
        $httpTool = new HttpTool($config);
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
    public function createHttpSocket($params = array())
    {
        return new HttpTool($params);
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
