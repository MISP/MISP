<?php
namespace MispToMispInterconnector;
require_once(ROOT . '/src/Lib/default/local_tool_interconnectors/CommonTools.php');
use CommonTools\CommonTools;
use Cake\Http\Client;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Client\Response;

class MispToMispInterconnector extends CommonTools
{
    protected $connects = ['MispConnector', 'MispConnector'];

    public function connect($connection1, $connection2, $params): bool
    {

    }
}

?>
