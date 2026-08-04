<?php
class GraphvizDOTTool
{
    const NODE_STYLE = [
        'trigger' => [
            'margin' => 0,
            'shape' => 'diamond',
        ],
        'logic' => [
            'margin' => 0,
            'shape' => 'parallelogram',
        ],
        'action' => [
            'margin' => 0,
            'shape' => 'box',
        ],
    ];
    const EDGE_STYLE = [
    ];

    /**
     * dot Get DOT language format of the provided graph
     *
     * @return string
     */
    public static function dot(array $graph_data)
    {
        $parsedGraph = self::__parseGraph($graph_data);
        $str = self::__header();
        $str .= self::__nodes($parsedGraph['nodes']);
        $str .= self::__edges($parsedGraph['edges']);
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
        return 'digraph G {' . PHP_EOL;
    }

    private static function __footer()
    {
        return '}';
    }

    private static function __nodes($nodes)
    {
        $str = '  {' . PHP_EOL;
        foreach ($nodes as $node) {
            $str .= '    ' . self::__node($node);
        }
        $str .= '  }' . PHP_EOL;
        return $str;
    }

    private static function __node(array $node)
    {
        $node_attributes = self::NODE_STYLE[$node['data']['module_type']];
        $node_attributes['label'] = $node['data']['name'];
        $node_attributes_text = self::__arrayToAttributes($node_attributes);
        return sprintf('%s [%s]' . PHP_EOL, $node['id'], $node_attributes_text);
    }

    private static function __edges($edges)
    {
        $str = '';
        foreach ($edges as $source_id => $target_ids) {
            foreach ($target_ids as $target_id) {
                $str .= '    ' . self::__edge($source_id, $target_id);
            }
        }
        return $str;
    }

    private static function __edge($source_id, $target_id)
    {
        return sprintf('%s -> %s [%s]' . PHP_EOL, $source_id, $target_id, self::__arrayToAttributes(self::EDGE_STYLE));
    }

    private static function __arrayToAttributes(array $list)
    {
        return implode(', ', array_map(function ($key, $value) {
            return sprintf('%s="%s"', $key, $value);
        }, array_keys($list), $list));
    }
}
