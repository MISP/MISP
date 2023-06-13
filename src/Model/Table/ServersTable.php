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

class ServersTable extends AppTable
{
}
