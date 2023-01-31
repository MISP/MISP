<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use App\Model\Entity\User;
use App\Http\Exception\TooManyRequestsException;
use Cake\ORM\TableRegistry;
use Cake\Core\Configure;
use Cake\Core\Configure\Engine\PhpConfig;

class FloodProtectionComponent extends Component
{
    private $remote_ip = null;
    private $FloodProtections = null;

    public function initialize(array $config): void
    {
        $ip_source = Configure::check('security.logging.ip_source') ? Configure::read('security.logging.ip_source') : 'REMOTE_ADDR';
        if (!isset($_SERVER[$ip_source])) {
            $ip_source = 'REMOTE_ADDR';
        }
        if (isset($_SERVER[$ip_source])) {
            $this->remote_ip = $_SERVER[$ip_source];
        } else {
            $this->remote_ip = '127.0.0.1';
        }
        $temp = explode(PHP_EOL, $_SERVER[$ip_source]);
        if (count($temp) > 1) {
            $this->remote_ip = $temp[0];
        }
        $this->FloodProtections = TableRegistry::getTableLocator()->get('FloodProtections');
    }

    public function check(string $action, int $limit = 5, int $expiration_time = 300): bool
    {
        $results = $this->FloodProtections->find()->where(['request_action' => $action, 'remote_ip' => $this->remote_ip, 'expiration' > time()])->all()->toList();
        if (count($results) >= $limit) {
            throw new TooManyRequestsException(__('Too many {0} requests have been issued ({1} requests allowed ever {2} seconds)', [$action, $limit, $expiration_time]));
        }
        return false;
    }

    public function set(string $action, int $expiration_time = 300): bool
    {
        $entry = $this->FloodProtections->newEmptyEntity();
        $entry->expiration = time() + $expiration_time;
        $entry->remote_ip = $this->remote_ip;
        $entry->request_action = $action;
        return (bool)$this->FloodProtections->save($entry);

    }

    public function checkAndSet(string $action, int $limit = 5, int $expiration_time = 300): bool
    {
        $result = $this->check($action, $limit, $expiration_time);
        $this->set($action, $expiration_time);
        return $result;
    }

    public function cleanup(): void
    {
        $this->FloodProtections->deleteAll(['expiration <' => time()]);
    }
}
