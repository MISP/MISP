<?php
App::uses('FontAwesomeHelper', 'View/Helper');

class MermaidFlowchartTool
{
    const NODE_STYLE = [
        'trigger' => '{{%s}}',
        'logic' => '[/%s/]',
        'action' => '[%s]',
    ];

    /**
     * dot Get DOT language format of the provided graph
     *
     * @return string
     */
    public static function mermaid(array $graph_data)
    {
        $parsedGraph = self::__parseGraph($graph_data);
        $str = self::__header();
        $str .= self::__nodes($parsedGraph['nodes'], $parsedGraph['edges']);
        $str .= self::__footer();
        return $str;
    }

    private static function __parseGraph($graph_data)
    {
        $graphUtil = new GraphUtil($graph_data);
        $nodes = $graphUtil->graph;
        $edges = $graphUtil->edgeList;
        return [
            'nodes' => $nodes,
            'edges' => $edges,
        ];
    }

    private static function __header()
    {
        return 'flowchart LR' . PHP_EOL;
    }

    private static function __footer()
    {
        return '';
    }

    private static function __nodes($nodes, $edges)
    {
        $str = '';
        foreach ($nodes as $node) {
            $str .= self::__node($nodes, $node, $edges[$node['id']]);
        }
        return $str;
    }

    private static function __node(array $all_nodes, array $node, array $edges)
    {
        $str = '';
        foreach ($edges as $target_id) {
            $target_node = $all_nodes[$target_id];
            $sourceNode = self::__singleNode($node);
            $targetNode = self::__singleNode($target_node);
            $str .= '    ' . sprintf('%s --> %s', $sourceNode, $targetNode) . PHP_EOL;
        }
        return $str;
    }

    private static function __singleNode(array $node)
    {
        $str = $node['id'];
        $icon = sprintf("%s:fa-%s ", FontAwesomeHelper::findNamespace($node['data']['icon']), $node['data']['icon']);
        $node_content = sprintf('"%s%s"',(!empty($node['data']['icon']) ? "$icon " : ''), $node['data']['name']);
        $str .= sprintf(
            self::NODE_STYLE[$node['data']['module_type']],
            $node_content
        );
        return $str;
    }
}
