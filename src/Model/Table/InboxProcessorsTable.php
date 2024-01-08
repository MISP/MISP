<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Filesystem\Folder;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Core\Exception\Exception;

class MissingInboxProcessorException extends Exception
{
    protected $_defaultCode = 404;
}

class InboxProcessorsTable extends AppTable
{
    private $processorsDirectory = ROOT . '/libraries/default/InboxProcessors';
    private $inboxProcessors;
    private $enabledProcessors = [ // to be defined in config
        'Proposal' => [
            'ProposalEdit' => false,
        ],
        'User' => [
            'Registration' => true,
        ],
    ];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->loadProcessors();
    }

    public function getProcessor($scope, $action=null)
    {
        if (isset($this->inboxProcessors[$scope])) {
            if (is_null($action)) {
                return $this->inboxProcessors[$scope];
            } else if (!empty($this->inboxProcessors[$scope]->{$action})) {
                return $this->inboxProcessors[$scope]->{$action};
            } else {
                throw new \Exception(__('Processor {0}.{1} not found', $scope, $action));
            }
        }
        throw new MissingInboxProcessorException(__('Processor not found'));
    }

    public function listProcessors($scope=null)
    {
        if (is_null($scope)) {
            return $this->inboxProcessors;
        } else {
            if (isset($this->inboxProcessors[$scope])) {
                return $this->inboxProcessors[$scope];
            } else {
                throw new MissingInboxProcessorException(__('Processors for {0} not found', $scope));
            }
        }
    }

    private function loadProcessors()
    {
        $processorDir = new Folder($this->processorsDirectory);
        $processorFiles = $processorDir->find('.*InboxProcessor\.php', true);
        foreach ($processorFiles as $processorFile) {
            if ($processorFile == 'GenericInboxProcessor.php') {
                continue;
            }
            $processorMainClassName = str_replace('.php', '', $processorFile);
            $processorMainClassNameShort = str_replace('InboxProcessor.php', '', $processorFile);
            $processorMainClass = $this->getProcessorClass($processorDir->pwd() . DS . $processorFile, $processorMainClassName);
            if (is_object($processorMainClass)) {
                $this->inboxProcessors[$processorMainClassNameShort] = $processorMainClass;
                foreach ($this->inboxProcessors[$processorMainClassNameShort]->getRegisteredActions() as $registeredAction) {
                    $scope = $this->inboxProcessors[$processorMainClassNameShort]->getScope();
                    if (!empty($this->enabledProcessors[$scope][$registeredAction])) {
                        $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction}->enabled = true;
                    } else {
                        $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction}->enabled = false;
                    }
                }
            } else {
                $this->inboxProcessors[$processorMainClassNameShort] = new \stdClass();
                $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction} = new \stdClass();
                $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction}->action = "N/A";
                $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction}->enabled = false;
                $this->inboxProcessors[$processorMainClassNameShort]->{$registeredAction}->error = $processorMainClass;
            }
        }
    }
    
    /**
     * getProcessorClass
     *
     * @param  string $filePath
     * @param  string $processorMainClassName
     * @return object|string Object loading success, string containing the error if failure
     */
    private function getProcessorClass($filePath, $processorMainClassName)
    {
        try {
            require_once($filePath);
            try {
                $reflection = new \ReflectionClass($processorMainClassName);
            } catch (\ReflectionException $e) {
                return $e->getMessage();
            }
            $processorMainClass = $reflection->newInstance(true);
            if ($processorMainClass->checkLoading() === 'Assimilation successful!') {
                return $processorMainClass;
            }
        } catch (Exception $e) {
            return $e->getMessage();
        }
    }
    
    /**
     * createInboxEntry
     *
     * @param  Object|Array $processor can either be the processor object or an array containing data to fetch it
     * @param  Array $data
     * @return Array
     */
    public function createInboxEntry($processor, $data)
    {
        if (!is_object($processor) && !is_array($processor)) {
            throw new MethodNotAllowedException(__("Invalid processor passed"));
        }
        if (is_array($processor)) {
            if (empty($processor['scope']) || empty($processor['action'])) {
                throw new MethodNotAllowedException(__("Invalid data passed. Missing either `scope` or `action`"));
            }
            $processor = $this->getProcessor('User', 'Registration');
        }
        return $processor->create($data);
    }
}
