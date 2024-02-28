<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;

class NotificationLogsTable extends AppTable
{
    private $__counter = 0;

    public function addEntry($org_id, $type)
    {
        $this->cleanup();
        $notification = $this->newEntity(array(
            'org_id' => $org_id,
            'type' => $type,
            'timestamp' => time()
        ));
        $this->save($notification);
        return true;
    }

    public function cleanup()
    {
        if ($this->__counter % 100 === 0) {
            $time_limit = time() - 86400;
            $this->deleteAll(
                array(
                    'NotificationLog.timestamp <' => $time_limit
                )
            );
        }
        $this->__counter++;
        return true;
    }

    public function check($org_id, $type)
    {
        $this->addEntry($org_id, $type);
        $this->cleanup();
        if (!empty(Configure::read('MISP.org_alert_threshold'))) {
            $count = $this->find('count', array(
                'conditions' => array(
                    'org_id' => $org_id,
                    'type' => $type
                )
            ));
            if ((int)Configure::read('MISP.org_alert_threshold') <= ($count)) {
                return false;
            }
        }
        return true;
    }
}
