<?php

class CyclicGraphException extends Exception {}

class GraphUtil
{
    public function __construct($graphData)
    {
        $this->graph = array_filter($graphData, function($i) {
            return $i != '_frames';
        }, ARRAY_FILTER_USE_KEY);
        $this->numberNodes = count($this->graph);
        $this->edgeList = $this->_buildEdgeList($this->graph);
        $this->properties = [];
    }

    private function _buildEdgeList($graphData): array
    {
        $list = [];
        foreach ($graphData as $i => $node) {
            $list[(int)$node['id']] = [];
            foreach (($node['outputs'] ?? []) as $output_id => $outputs) {
                foreach ($outputs as $connections) {
                    foreach ($connections as $connection) {
                        $list[$node['id']][] = (int)$connection['node'];
                    }
                }
            }
        }
        return $list;
    }

    private function _DFSUtil($node_id, &$color): bool
    {
        $color[$node_id] = 'GRAY';
        foreach ($this->edgeList[$node_id] as $i) {
            if ($color[$i] == 'GRAY') {
                $this->loopNode = $i;
                $this->properties[] = [$node_id, $i, __('Cycle')];
                return true;
            }
            if ($color[$i] == 'WHITE' && $this->_DFSUtil($i, $color)) {
                if (!is_null($this->loopNode)) {
                    $this->properties[] = [$node_id, $i, __('Cycle')];
                    if ($this->loopNode == $node_id) {
                        $this->loopNode = null;
                    }
                }
                return true;
            }
        }
        $color[$node_id] = 'BLACK';
        return false;
    }

    /**
     * isCyclic Return is the graph is cyclic, so if it contains a cycle.
     * 
     * A directed graph G is acyclic if and only if a depth-first search of G yields no back edges.
     * Introduction to Algorithms, third edition By Thomas H. Cormen, Charles E. Leiserson, Ronald L. Rivest, Clifford Stein
     *
     * @return array
     */
    public function isCyclic(): array
    {
        $this->properties = [];
        $color = [];
        foreach (array_keys($this->edgeList) as $node_id) {
            $color[$node_id] = 'WHITE';
        }

        $this->loopNode = null;
        foreach (array_keys($this->edgeList) as $node_id) {
            if ($color[$node_id] == 'WHITE') {
                if ($this->_DFSUtil($node_id, $color)) {
                    return [true, $this->properties];
                }
            }
        }
        return [false, []];
    }

    public function hasMultipleOutputConnection(): array
    {
        $edges = [];
        foreach ($this->graph as $node) {
            foreach (($node['outputs'] ?? []) as $output_id => $outputs) {
                foreach ($outputs as $connections) {
                    if (count($connections) > 1 && empty($node['data']['multiple_output_connection'])) {
                        $edges[$node['id']] = array_map(function ($connection) {
                            return intval($connection['node']);
                        }, $connections);
                    }
                }
            }
        }
        return [!empty($edges), $edges];
    }
}

class GraphWalker
{
    private $graph;
    private $WorkflowModel;
    private $startNodeID;
    private $for_path;
    private $cursor;

    const PATH_TYPE_BLOCKING = 'blocking';
    const PATH_TYPE_NON_BLOCKING = 'non-blocking';
    const PATH_TYPE_INCLUDE_LOGIC = 'include-logic';
    const ALLOWED_PATH_TYPES = [GraphWalker::PATH_TYPE_BLOCKING, GraphWalker::PATH_TYPE_NON_BLOCKING, GraphWalker::PATH_TYPE_INCLUDE_LOGIC];

    public function __construct(array $graphData, $WorkflowModel, $startNodeID, $for_path=null)
    {
        $this->graph = $graphData;
        $this->WorkflowModel = $WorkflowModel;
        $this->startNodeID = $startNodeID;
        $this->for_path = $for_path;
        $this->triggersByNodeID = [];
        if (empty($this->graph[$startNodeID])) {
            throw new Exception(__('Could not find start node %s', $startNodeID));
        }
        $this->cursor = $startNodeID;
    }

    private function getModuleClass($node)
    {
        $moduleClass = $this->loaded_classes[$node['data']['module_type']][$node['data']['id']] ?? null;
        return $moduleClass;
    }

    private function _getPathType($node_id, $path_type)
    {
        $node = $this->graph[$node_id];
        if ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'concurrent-task') {
            return self::PATH_TYPE_NON_BLOCKING;
        }
        return $path_type;
    }


    private function _evaluateOutputs($node, WorkflowRoamingData $roamingData, $shouldExecuteLogicNode=true)
    {
        $allowed_outputs = ($node['outputs'] ?? []);
        if ($shouldExecuteLogicNode && $node['data']['module_type'] == 'logic') {
            $allowed_outputs = $this->_executeModuleLogic($node, $roamingData);
        }
        return $allowed_outputs;
    }

    /**
     * _executeModuleLogic function
     *
     * @param array $node
     * @return array
     */
    private function _executeModuleLogic(array $node, WorkflowRoamingData $roamingData): array
    {
        $outputs = ($node['outputs'] ?? []);
        if ($node['data']['id'] == 'if') {
            $useFirstOutput = $this->_evaluateIFCondition($node, $roamingData);
            return $useFirstOutput ? ['output_1' => $outputs['output_1']] : ['output_2' => $outputs['output_2']];
        } else if ($node['data']['id'] == 'concurrent-task') {
            $this->_evaluateConcurrentTask($node, $roamingData, $outputs['output_1']);
            return ['output_1' => []];
        } else if ($node['data']['id'] == 'generic-filter-data') {
            $this->_evaluateFilterAddLogic($node, $roamingData, $outputs['output_1']);
            return ['output_1' => $outputs['output_1']];
        } else if ($node['data']['id'] == 'generic-filter-reset') {
            $this->_evaluateFilterRemoveLogic($node, $roamingData, $outputs['output_1']);
            return ['output_1' => $outputs['output_1']];
        } else {
            $useFirstOutput = $this->_evaluateCustomLogicCondition($node, $roamingData);
            return $useFirstOutput ? ['output_1' => $outputs['output_1']] : ['output_2' => $outputs['output_2']];
        }
        return $outputs;
    }

    private function _evaluateIFCondition($node, WorkflowRoamingData $roamingData): bool
    {
        $result = $this->WorkflowModel->executeNode($node, $roamingData);
        return $result;
    }

    private function _evaluateFilterAddLogic($node, WorkflowRoamingData $roamingData): bool
    {
        $result = $this->WorkflowModel->executeNode($node, $roamingData);
        return $result;
    }

    private function _evaluateFilterRemoveLogic($node, WorkflowRoamingData $roamingData): bool
    {
        $result = $this->WorkflowModel->executeNode($node, $roamingData);
        return $result;
    }

    private function _evaluateCustomLogicCondition($node, WorkflowRoamingData $roamingData): bool
    {
        $result = $this->WorkflowModel->executeNode($node, $roamingData);
        return $result;
    }

    private function _evaluateConcurrentTask($concurrent_node, WorkflowRoamingData $roamingData, array $connections)
    {
        foreach ($connections['connections'] as $connection) {
            $node_id_to_exec = (int)$connection['node'];
            $data = $roamingData->getData();
            $data['__node_id_to_exec'] = $node_id_to_exec;
            $data = $roamingData->setData($data);
            $this->WorkflowModel->executeNode($concurrent_node, $roamingData);
        }
    }

    public function _walk($node_id, $path_type=null, array $path_list=[], WorkflowRoamingData $roamingData)
    {
        $this->cursor = $node_id;
        $node = $this->graph[$node_id];
        $shouldExecuteLogicNode = $path_type != self::PATH_TYPE_INCLUDE_LOGIC;
        if (!$shouldExecuteLogicNode) {
            yield ['node' => $node, 'path_type' => $path_type, 'path_list' => $path_list];
        } else if ($node['data']['module_type'] != 'trigger' && $node['data']['module_type'] != 'logic') { // trigger and logic nodes should not be returned as they are "control" nodes
            yield ['node' => $node, 'path_type' => $path_type, 'path_list' => $path_list];
        }
        $allowedOutputs = $this->_evaluateOutputs($node, $roamingData, $shouldExecuteLogicNode);
        foreach ($allowedOutputs as $output_id => $outputs) {
            if ($shouldExecuteLogicNode) {
                $path_type = $this->_getPathType($node_id, $path_type);
            }
            if (is_null($this->for_path) || $path_type == $this->for_path) {
                foreach ($outputs as $connections) {
                    foreach ($connections as $connection_id => $connection) {
                        $next_node_id = (int)$connection['node'];
                        $current_path = $this->__genPathList($node_id, $output_id, $connection_id, $next_node_id);
                        if (in_array($current_path, $path_list)) { // avoid loops
                            continue;
                        }
                        $next_path_list = $path_list;
                        $next_path_list[] = $current_path;
                        yield from $this->_walk($next_node_id, $path_type, $next_path_list, $roamingData);
                    }
                }
            }
        }
    }

    public function walk(WorkflowRoamingData $roamingData)
    {
        return $this->_walk($this->cursor, $this->for_path, [], $roamingData);
    }

    private function __genPathList($source_id, $output_id, $connection_id, $next_node_id)
    {
        return sprintf('%s:%s:%s:%s', $source_id, $output_id, $connection_id, $next_node_id);
    }

    public static function parsePathList($pathList): array
    {
        return array_map(function($path) {
            $split = explode(':', $path);
            return [
                'source_id' => $split[0],
                'output_id' => $split[1],
                'connection_id' => $split[2],
                'next_node_id' => $split[3],
            ];
        }, $pathList);
    }
}

class WorkflowRoamingData
{
    private $workflow_user;
    private $data;
    private $workflow;
    private $current_node;
    private $trigger_node;
    private $workflowModel;

    public function __construct(array $workflow_user, array $data, array $workflow, int $current_node, $trigger_node)
    {
        $this->workflow_user = $workflow_user;
        $this->data = $data;
        $this->workflow = $workflow;
        $this->current_node = $current_node;
        $this->trigger_node = $trigger_node;
    }

    public function getUser(): array
    {
        return $this->workflow_user;
    }

    public function getData(): array
    {
        if (!empty($this->getEnabledFilters())) {
            return $this->filterDataIfNeeded();
        }
        return $this->data;
    }

    public function filterDataIfNeeded(): array
    {
        $filteredData = $this->data;
        $filters = $this->getEnabledFilters();
        foreach ($filters as $filteringLabel => $filteringOptions) {
            $filteredData = $this->applyFilter($filteredData, $filteringOptions);
        }
        return $filteredData;
    }

    private function applyFilter(array $data, array $filteringOptions): array
    {
        if (substr($filteringOptions['selector'], -4) === '.{n}') {
            $filteringOptions['selector'] = substr($filteringOptions['selector'], 0, -4);
        }
        $baseModule = $this->getFilteringModule();
        $extracted = $baseModule->extractData($data, $filteringOptions['selector']);
        if ($extracted === false) {
            $filteredData = false;
        }
        $filteredData = $baseModule->getItemsMatchingCondition($extracted, $filteringOptions['value'], $filteringOptions['operator'], $filteringOptions['path']);
        $newData = Hash::remove($data, $filteringOptions['selector']);
        $newData = Hash::insert($data, $filteringOptions['selector'], $filteredData);
        return $newData;
    }

    private function getFilteringModule()
    {
        $this->workflowModel = ClassRegistry::init('Workflow');
        $moduleClass = $this->workflowModel->getModuleClassByType('logic', 'generic-filter-data');
        return $moduleClass;
    }

    public function getEnabledFilters(): array
    {
        return !empty($this->data['enabledFilters']) ? $this->data['enabledFilters'] : [];
    }

    public function getWorkflow(): array
    {
        return $this->workflow;
    }

    public function getCurrentNode(): int
    {
        return $this->current_node;
    }

    public function getTriggerNode(): array
    {
        return $this->trigger_node;
    }

    public function setData(array $data)
    {
        $this->data = $data;
    }

    public function setCurrentNode(int $current_node)
    {
        $this->current_node = $current_node;
    }
}

class WorkflowGraphTool
{

    /**
     * cleanGraphData Remove frame nodes from the graph data
     *
     * @param  array $graphData
     * @return array
     */
    public static function cleanGraphData(array $graphData): array
    {
        return array_filter($graphData, function($i) {
            return $i != '_frames';
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * extractTriggerFromWorkflow Return the trigger id (or full module) that are specified in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return int|array|null
     */
    public static function extractTriggerFromWorkflow(array $graphData, bool $fullNode = false)
    {
        $triggers = self::extractTriggersFromWorkflow($graphData, $fullNode);
        if (empty($triggers)) {
            return null;
        }
        $node = $triggers[0];
        return $node;
    }

    /**
     * extractTriggersFromWorkflow Return the list of triggers id (or full module) that are specified in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return array
     */
    public static function extractTriggersFromWorkflow(array $graphData, bool $fullNode = false): array
    {
        $graphData = self::cleanGraphData($graphData);
        $triggers = [];
        foreach ($graphData as $i => $node) {
            if ($node['data']['module_type'] == 'trigger') {
                if (!empty($fullNode)) {
                    $triggers[] = $node;
                } else {
                    $triggers[] = $node['data']['id'];
                }
            }
        }
        return $triggers;
    }

    /**
     * extractConcurrentTasksFromWorkflow Return the list of concurrent-tasks's id (or full module) that are included in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return array
     */
    public static function extractConcurrentTasksFromWorkflow(array $graphData, bool $fullNode = false): array
    {
        $graphData = self::cleanGraphData($graphData);
        $nodes = [];
        foreach ($graphData as $i => $node) {
            if ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'concurrent-task') {
                if (!empty($fullNode)) {
                    $nodes[] = $node;
                } else {
                    $nodes[] = $node['data']['id'];
                }
            }
        }
        return $nodes;
    }

    /**
     * extractFilterNodesFromWorkflow Return the list of generic-filter-data's id (or full module) that are included in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return array
     */
    public static function extractFilterNodesFromWorkflow(array $graphData, bool $fullNode = false): array
    {
        $graphData = self::cleanGraphData($graphData);
        $nodes = [];
        foreach ($graphData as $i => $node) {
            if ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'generic-filter-data') {
                if (!empty($fullNode)) {
                    $nodes[] = $node;
                } else {
                    $nodes[] = $node['data']['id'];
                }
            }
        }
        return $nodes;
    }

    /**
     * extractResetFilterFromWorkflow Return the list of generic-filter-reset's id (or full module) that are included in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return array
     */
    public static function extractResetFilterFromWorkflow(array $graphData, bool $fullNode = false): array
    {
        $graphData = self::cleanGraphData($graphData);
        $nodes = [];
        foreach ($graphData as $i => $node) {
            if ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'generic-filter-reset') {
                if (!empty($fullNode)) {
                    $nodes[] = $node;
                } else {
                    $nodes[] = $node['data']['id'];
                }
            }
        }
        return $nodes;
    }

    /**
     * isAcyclic Return if the graph contains a cycle
     *
     * @param array $graphData
     * @param array $cycles Get a list of cycle
     * @return boolean
     */
    public static function isAcyclic(array $graphData, array &$cycles=[]): bool
    {
        $graphUtil = new GraphUtil($graphData);
        $result = $graphUtil->isCyclic();
        $isCyclic = $result[0];
        $cycles = $result[1];
        return !$isCyclic;
    }

    /**
     * hasMultipleOutputConnection Return if the graph has multiple connection from a node output
     *
     * @param array $graphData
     * @param array $edges Get a list of edges from the same output
     * @return boolean
     */
    public static function hasMultipleOutputConnection(array $graphData, array &$edges=[]): bool
    {
        $graphUtil = new GraphUtil($graphData);
        $result = $graphUtil->hasMultipleOutputConnection();
        $hasMultipleOutputConnection = $result[0];
        $edges = $result[1];
        return $hasMultipleOutputConnection;
    }

    /**
     * Undocumented getNodeIdForTrigger
     *
     * @param array $graphData 
     * @param string $trigger_id
     * @return integer Return the ID of the node for the provided trigger and -1 if no nodes with this id was found.
     */
    public static function getNodeIdForTrigger(array $graphData, $trigger_id): int
    {
        $trigger_node = WorkflowGraphTool::extractTriggerFromWorkflow($graphData, true);
        if ($trigger_node['data']['id'] == $trigger_id) {
            return $trigger_node['id'];
        }
        return -1;
    }

    public static function getRoamingData(array $user=[], array $data=[], array $workflow=[], int $node_id=-1, array $trigger_node = null)
    {
        return new WorkflowRoamingData($user, $data, $workflow, $node_id, $trigger_node);
    }

    public static function getWalkerIterator(array $graphData, $WorkflowModel, $startNodeID, $path_type=null, WorkflowRoamingData $roamingData)
    {
        if (!in_array($path_type, GraphWalker::ALLOWED_PATH_TYPES)) {
            return [];
        }
        $graphWalker = new GraphWalker($graphData, $WorkflowModel, $startNodeID, $path_type);
        return $graphWalker->walk($roamingData);
    }
}
