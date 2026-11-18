<?php
/**
 * The value page's analyst items in the shape AnalystData/thread reads, so
 * the Collaboration tab's Notes and opinions and the Relationships tab's
 * Asserted by analysts draw them the one way.
 */
class ValueAnalystThreadTool
{
    /**
     * A note or an opinion, with its replies nested. What the host's
     * context line needs travels under `_target` and `_rates`.
     *
     * @param array $item A ValueIntelligence analyst item
     * @return array
     */
    public static function row(array $item)
    {
        $row = array(
            'id' => $item['id'] ?? null,
            'uuid' => $item['uuid'] ?? null,
            'created' => $item['created'] ?? $item['date'],
            'distribution' => $item['distribution'],
            'authors' => $item['author'],
            'Orgc' => array('name' => $item['org']),
            '_canEdit' => !empty($item['can_edit']),
            '_max_depth_reached' => !empty($item['max_depth_reached']),
            '_target' => $item['attached_to'] ?? null,
            '_rates' => $item['rates'] ?? 'value',
            'Note' => array(),
            'Opinion' => array(),
        );
        if ($item['kind'] === 'opinion') {
            $row['opinion'] = (int)$item['score'];
            $row['comment'] = $item['body'];
        } else {
            $row['note'] = $item['body'];
        }
        foreach ($item['children'] ?? array() as $child) {
            $row[$child['kind'] === 'opinion' ? 'Opinion' : 'Note'][] = self::row($child);
        }
        return $row;
    }
}
