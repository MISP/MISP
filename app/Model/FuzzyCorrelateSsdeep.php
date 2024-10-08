<?php
App::uses('AppModel', 'Model');

class FuzzyCorrelateSsdeep extends AppModel
{
    public $useTable = 'fuzzy_correlate_ssdeep';

    public $recursive = -1;

    public function ssdeep_prepare($hash)
    {
        list($blockSize, $hash) = explode(':', $hash, 2);

        $uniqueChars = array_unique(str_split($hash), SORT_REGULAR);

        $search = true;
        while ($search) {
            $search = false;
            foreach ($uniqueChars as $c) {
                if (str_contains($hash, $c . $c . $c . $c)) {
                    $hash = str_replace($c . $c . $c . $c, $c . $c . $c, $hash);
                    $search = true;
                }
            }
        }

        $hash = explode(':', $hash);
        list($block_data, $double_block_data) = $hash;

        return [
            $blockSize,
            $this->getAll7CharChunks($block_data),
            $this->getAll7CharChunks($double_block_data)
        ];
    }

    private function getAll7CharChunks($hash)
    {
        $results = array();
        for ($i = 0; $i < strlen($hash) - 6; $i++) {
            $current = substr($hash, $i, 7);
            $temp = $current . '=';
            $temp = base64_decode($temp);
            $temp = $temp . "\x00\x00\x00";
            $temp = base64_encode($temp);
            if (!in_array($temp, $results, true)) {
                $results[] = $temp;
            }
        }
        return $results;
    }

    /**
     * @param string $hash
     * @param int $attributeId
     * @return array
     */
    public function query_ssdeep_chunks($hash, $attributeId)
    {
        $chunks = $this->ssdeep_prepare($hash);
        $bothPartChunks = array_merge($chunks[1], $chunks[2]);
        
        // Original algo from article https://www.virusbulletin.com/virusbulletin/2015/11/optimizing-ssdeep-use-scale
        // also propose to insert chunk size to database, but current database schema doesn't contain that column.
        // This optimisation can be add in future versions.
        $result = $this->find('column', array(
            'conditions' => array(
                'FuzzyCorrelateSsdeep.chunk' => $bothPartChunks,
            ),
            'fields' => array('FuzzyCorrelateSsdeep.attribute_id'),
            'unique' => true,
        ));
        
        $toSave = [];
        $attributeId = (int) $attributeId;
        foreach ($bothPartChunks as $chunk) {
            $toSave[] = [$attributeId, $chunk];
        }
        $db = $this->getDataSource();
        $db->insertMulti($this->table, ['attribute_id', 'chunk'], $toSave);
        return $result;
    }

    /**
     * @param int|null $eventId
     * @param int|null $attributeId
     * @return bool True on success, false on failure
     */
    public function purge($eventId = null, $attributeId = null)
    {
        if (!$eventId && !$attributeId) {
            $this->query('TRUNCATE TABLE fuzzy_correlate_ssdeep;');
        } elseif (!$attributeId) {
            $this->Attribute = ClassRegistry::init('MispAttribute');
            $attributeId = $this->Attribute->find('column', array(
                'conditions' => array(
                    'Attribute.event_id' => $eventId,
                    'Attribute.type' => 'ssdeep',
                ),
                'fields' => ['Attribute.id'],
            ));
            if (empty($attributeId)) {
                return true;
            }
        }

        return $this->deleteAll(array('FuzzyCorrelateSsdeep.attribute_id' => $attributeId), false);
    }
}
