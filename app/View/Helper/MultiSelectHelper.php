<?php
App::uses('AppHelper', 'View/Helper');

// helper function used by the index table to extract multi select data
// Declared as a helper to avoid code duplication
class MultiSelectHelper extends AppHelper {

    public function getMultiSelectData($topbar)
    {
        foreach ($topbar['children'] as $child) {
            if (!empty($child['type']) && $child['type'] == 'multi_select_actions') {
                return $child;
            }
        }
        return [];
    }
}
