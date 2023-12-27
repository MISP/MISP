<?php
namespace App\Model\Behavior;

use App\Lib\Tools\HttpTool;
use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Client;
use Cake\ORM\Behavior;
use Cake\Utility\Text;


/**
 * @deprecated SyncTool - use HttpTool instead
 */
class SyncTool extends Behavior
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
     * @return array
     * @throws Exception
     */
    private static function getClientCertificateInfo($certificateContent)
    {
        return HttpTool::getClientCertificateInfo($certificateContent);
    }

    /**
     * @param mixed $certificate
     * @return array
     * @throws Exception
     */
    private static function parseCertificate($certificate)
    {
        return HttpTool::parseCertificate($certificate);
    }
}
