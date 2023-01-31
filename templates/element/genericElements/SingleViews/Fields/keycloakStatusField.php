<?php

    use Cake\Utility\Hash;

    $value = Hash::get($data, $field['path']);
    $differencesRearranged = array_map(function($difference) {
        return [
            __('Local: {0}', h($difference['cerebrate'])),
            __('Keycloak: {0}', h($difference['keycloak'])),
        ];
    }, $value['differences']);
    if (!empty($value['require_update'])) {
        echo sprintf(
            '<div class="alert alert-warning"><div>%s</div>%s</div>',
            $this->Bootstrap->icon('exclamation-triangle') . __(' This user is not synchronised with Keycloak. Differences:'),
            $this->Html->nestedList($differencesRearranged, ['class' => ''])
        );
    } else {
        echo $this->Bootstrap->icon('check', ['class' => 'text-success',]);
    }
?>
