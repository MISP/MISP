<?php
    $timestamp = Hash::extract($row, $field['data_path'])[0];
    $enabled = isset($field['enabled_path']) ? Hash::extract($row, $field['enabled_path'])[0] : true;
    if (!empty($timestamp)):
        $units = array('m', 'h', 'd');
        $intervals = array(60, 60, 24);
        $unit = 's';
        $last = time() - $timestamp;
        foreach ($units as $k => $v) {
            if ($last > $intervals[$k]) {
                $unit = $v;
                $last = floor($last / $intervals[$k]);
            } else {
                break;
            }
        }
        $ageString = __('Age: ') . $last . $unit;
    else:
        $ageString =  __('Not cached');
    endif;
    echo sprintf(
        '<span class="%s">%s</span>%s',
        empty($timestamp) ? 'red bold' : '',
        h($ageString),
        (!$enabled || !$isSiteAdmin) ? '' : ' ' . $this->Form->postLink(
            '<span class="black fa fa-memory"></span>',
            $baseurl . '/feeds/cacheFeeds/' . h($primary),
            array(
                'escape' => false,
                'aria-label' => __('Cache feed'),
                'title' => __('Cache feed')
            )
        )
    );
?>
