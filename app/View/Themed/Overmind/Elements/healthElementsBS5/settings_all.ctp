<?php
/**
 * Every setting of the instance on one page, grouped by destination in the
 * order of the navigation. Nothing is hidden here: this is where the
 * advanced and deprecated settings, and the problems the Overview did not
 * list, are all reachable.
 */

$grouped = array();
foreach ($destinations as $id => $entry) {
    if (!empty($sectionsByDestination[$id])) {
        $grouped[$id] = $sectionsByDestination[$id];
    }
}

echo $this->element('healthElementsBS5/settings_page', array(
    'sections' => array(),
    'grouped' => $grouped,
    'tiered' => false,
));
