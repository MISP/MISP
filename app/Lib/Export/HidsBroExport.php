<?php

App::uses('HidsExport', 'Export');

/**
 * Created by IntelliJ IDEA.
 * User: ppanero
 * Date: 11/08/16
 * Time: 11:04
 */
class HidsBroExport extends HidsExport {


    // below overwrite functions from HidsExport
    public function export($items, $type = 'MD5', $continue = false) {

        $orgsName = array();
        if (!empty($items)) {
            foreach ($items as &$item) {
                $ruleFormatReference = Configure::read('MISP.baseurl') . '/events/view/' . $item['Event']['id'];
                if (array_key_exists($item['Event']['orgc_id'], $orgsName)) {
                    $orgName = $orgsName[$item['Event']['orgc_id']];
                } else {
                    $orgModel = ClassRegistry::init('Organisation');
                    $org = $orgModel->find('first', array(
                            'fields' => array('Organisation.name'),
                            'conditions' => array('id' => $item['Event']['orgc_id']),
                        )
                    );
                    $orgName = $org['Organisation']['name'];
                    $orgsName[$item['Event']['orgc_id']] = $orgName;
                }
                $orgFormatReference = $orgName;
                $ruleFormat = "%s\t%s\t" . $orgFormatReference . "\t" . $ruleFormatReference . "\t%s\t%s";
                $attribute = &$item['Attribute'];

                $this->rules[] = sprintf($ruleFormat,
                    $attribute['value'],			// hash value
                    'Intel:FILE_HASH',				// type
                    'T',						    // meta.do_notice
                    '-'                             // meta.if_in
                );
            }
        }
        if (!$continue) $this->explain($type);
        return $this->rules;
    }
}