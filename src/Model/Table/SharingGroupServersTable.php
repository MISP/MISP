<?php

namespace App\Model\Table;

use App\Model\Entity\SharingGroup;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\RulesChecker;
use Cake\Utility\Text;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use InvalidArgumentException;
use App\Model\Entity\Log;

class SharingGroupServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Servers',
            [
                'foreignKey' => 'server_id',
            ]
        );

        $this->belongsTo(
            'SharingGroups',
            [
                'foreignKey' => 'sharing_group_id',
            ]
        );
    }
}
