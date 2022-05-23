<?php

class CyclicGraphException extends Exception {}

class GraphUtil
{
    public function __construct($graphData)
    {
        $this->graph = $graphData;
        $this->numberNodes = count($this->graph);
        $this->edgeList = $this->_buildEdgeList($graphData);
        $this->properties = [];
    }

    private function _buildEdgeList($graphData): array
    {
        $list = [];
        foreach ($graphData as $node) {
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

    private function _DFSUtil($node_id, &$color, $depth=0): bool
    {
        $color[$node_id] = 'GRAY';
        foreach ($this->edgeList[$node_id] as $i) {
            if ($color[$i] == 'GRAY') {
                $this->properties[] = [$node_id, $i, __('Cycle')];
                return true;
            }
            if ($color[$i] == 'WHITE' && $this->_DFSUtil($i, $color, $depth+1)) {
                if ($depth > 0) {
                    $this->properties[] = [$node_id, $i, __('Cycle')];
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
        foreach (array_keys($this->edgeList) as $node_id) {
            if ($color[$node_id] == 'WHITE') {
                if ($this->_DFSUtil($node_id, $color)) {
                    return [true, $this->properties];
                }
            }
        }
        return [false, []];
    }
}

class GraphNavigator
{
    public function __construct(array $graphData, $startNodeID)
    {
        $this->graph = $graphData;
        $this->startNodeID = $startNodeID;
        $this->graphUtil = new GraphUtil($graphData);
        $this->edgeList = $this->graphUtil->edgeList;
        $this->triggersByNodeID = [];
        $this->triggersByModuleID = [];
        $this->setTriggers();
        if (empty($this->triggersByNodeID) || empty($this->triggersByModuleID[$this->startNodeID])) {
            throw new Exception(__('Could not find start node %s', $startNodeID), 1);
        }
        $this->cursor = $this->triggersByModuleID[$startNodeID];
        $this->path_type = null;
    }

    private function setTriggers(): array
    {
        $triggers = [];
        foreach ($this->graph as $node_id => $node) {
            if ($node['data']['module_type'] == 'trigger') {
                $this->triggersByNodeID[$node_id] = $node;
                $this->triggersByModuleID[$node['data']['id']] = $node_id;
            }
        }
        return $triggers;
    }

    private function _getPathType($node_id, $path_type, $output_id)
    {
        $node = $this->graph[$node_id];
        if (!empty($this->triggersByNodeID[$node_id])) {
            return $output_id == 'output_1' ? 'blocking' : 'parallel';
        } elseif ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'parallel-task') {
            return 'parallel';
        }
        return $path_type;
    }


    private function _evaluateOutputs($node_id, $outputs)
    {
        $node = $this->graph[$node_id];
        if ($node['data']['module_type'] == 'logic' && $node['data']['id'] == 'if') {
            $useThenBranch = $this->_evaluateIFCondition($node);
            return $useThenBranch ? ['output_1' => $outputs['output_1']] : ['output_2' => $outputs['output_2']];
        }
        return $outputs;
    }

    private function _evaluateIFCondition($node): bool
    {
        // $result = $node->execute();
        $result = true;
        return $result;
    }

    public function _navigate($node_id, $path_type=null)
    {
        $this->cursor = $node_id;
        $node = $this->graph[$node_id];
        if ($node['data']['module_type'] != 'trigger' && $node['data']['module_type'] != 'logic') { // trigger and logic nodes should not be returned as they are "control" nodes
            yield [$node_id, $path_type];
        }
        $outputs = ($node['outputs'] ?? []);
        $allowedOutputs = $this->_evaluateOutputs($node_id, $outputs);
        foreach ($allowedOutputs as $output_id => $outputs) {
            $path_type = $this->_getPathType($node_id, $path_type, $output_id);
            foreach ($outputs as $connections) {
                foreach ($connections as $connection) {
                    $next_node_id = (int)$connection['node'];
                    yield from $this->_navigate($next_node_id, $path_type);
                }
            }
        }
    }

    public function navigate()
    {
        return $this->_navigate($this->cursor);
    }
}

class WorkflowGraphTool
{

    const GRAPH_BLOCKING_CONNECTION_NAME = 'output_1';
    const GRAPH_NON_BLOCKING_CONNECTION_NAME = 'output_2';

    /**
     * extractTriggersFromWorkflow Return the list of trigger names (or full node) that are specified in the workflow
     *
     * @param  array $workflow
     * @param  bool $fullNode
     * @return array
     */
    public static function extractTriggersFromWorkflow(array $graphData, bool $fullNode = false): array
    {
        $triggers = [];
        foreach ($graphData['data'] as $node) {
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
     * triggerHasBlockingPath Return if the provided trigger has an edge leading to a blocking path
     * 
     * @param array $node
     * @returns bool
     */
    public static function triggerHasBlockingPath(array $node): bool
    {
        return !empty($node['outputs'][WorkflowGraphTool::GRAPH_BLOCKING_CONNECTION_NAME]['connections']);
    }

    /**
     * triggerHasBlockingPath Return if the provided trigger has an edge leading to a non-blocking path
     * 
     * @param array $node
     * @returns bool
     */
    public static function triggerHasNonBlockingPath(array $node): bool
    {
        return !empty($node['outputs'][WorkflowGraphTool::GRAPH_NON_BLOCKING_CONNECTION_NAME]['connections']);
    }

    /**
     * hisCyclic Return if the graph contains a cycle
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
        // try {
        //     WorkflowGraphTool::buildExecutionPath($graphData);
        // } catch (CyclicGraphException $e) {
        //     return false;
        // }
        // return true;
    }

    public static function getNavigatorIterator(array $graphData, $startNodeID)
    {
        $graphNavigator = new GraphNavigator($graphData, $startNodeID);
        return $graphNavigator->navigate();
    }
}
