<?php
App::uses('AppModel', 'Model');
class FuzzyCorrelateSsdeep extends AppModel
{
    public $useTable = 'fuzzy_correlate_ssdeep';

    public $recursive = -1;

    public $actsAs = array('Containable');

    public $validate = array();

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function ssdeep_prepare($hash)
    {
        $hash = explode(':', $hash);
        $block_size = $hash[0];
        unset($hash[0]);
        $hash = implode(':', $hash);
        $chars = array();
        for ($i = 0; $i < strlen($hash); $i++) {
            if (!in_array($hash[$i], $chars)) {
                $chars[] = $hash[$i];
            }
        };
        $search = true;
        while ($search) {
            $search = false;
            foreach ($chars as $k => $c) {
                if (strpos($hash, $c . $c . $c . $c)) {
                    $hash = str_replace($c . $c . $c . $c, $c . $c . $c, $hash);
                    $search = true;
                }
            }
        }
        $hash = explode(':', $hash);
        $block_data = $hash[0];
        $double_block_data = $hash[1];
        //        (struct.unpack("<Q", base64.b64decode(h[i:i + 7] + "=") + "\x00\x00\x00")[0] for i in range(len(h) - 6)))

        $result = array(
            $block_size,
            $this->get_all_7_char_chunks($block_data),
            $this->get_all_7_char_chunks($double_block_data)
        );
        return $result;
    }

    public function get_all_7_char_chunks($hash)
    {
        $result = '';
        $results = array();
        for ($i = 0; $i < strlen($hash) - 6; $i++) {
            $current = substr($hash, $i, 7);
            $temp = $current . '=';
            $temp = base64_decode($temp);
            $temp = $temp . "\x00\x00\x00";
            $temp = base64_encode($temp);
            if (!in_array($temp, $results)) {
                $results[] = $temp;
            }
        }
        return $results;
    }

    public function query_ssdeep_chunks($hash, $attribute_id)
    {
        //'12288:CeqW86Tf7xglFIV/4Zf8FkKBPFrmtJxv/znLABkeGevRcAqn9LqgqmlrexDvBIRF:CV6fxg7IeEOKXrmtJx3rLABk1eFElree'
        $chunks = $this->ssdeep_prepare($hash);
        // if chunk_size == chunk_size_1 OR 2*chunk_size == chunk_size
        // SELECT * from ssdeep_chunks where (chunk_size = $chunk_size OR chunk_size*2 = $chunk_size)
        //   AND chunk_size
        $result = $this->find('list', array(
            'conditions' => array(
                'AND' => array(
                    'OR' => array(
                        'FuzzyCorrelateSsdeep.chunk_size' => $chunks[0],
                        'FuzzyCorrelateSsdeep.chunk_size' => $chunks[0] * 2,
                    ),
                    'OR' => array(
                        'FuzzyCorrelateSsdeep.chunk' => $chunks[1],
                        'FuzzyCorrelateSsdeep.chunk' => $chunks[2]
                    )
                )
            ),
            'fields' => array('FuzzyCorrelateSsdeep.attribute_id', 'FuzzyCorrelateSsdeep.attribute_id')
        ));
        $to_save = array();
        foreach (array(1, 2) as $type) {
            foreach ($chunks[$type] as $chunk) {
                $to_save[] = array('attribute_id' => $attribute_id, 'chunk' => $chunk);
            }
        }
        $this->saveAll($to_save);
        return $result;
    }
}
