<div style="overflow-y:auto;<?= $persistent ? 'max-height:98%;padding: .3em 1em' : 'max-height:75vh' ?>">
<?php
$formatValue = function (array $attribute) {
    switch ($attribute['type']) {
        case 'link':
            return '<a href="' . h($attribute['value']) . '" rel="noreferrer noopener" target="_blank">' . h($attribute['value']) . '</a>';
        default:
            return h($attribute['value']);
    }
};
foreach ($results as $enrichment_type => $enrichment_values) {
    echo sprintf('<h5 class="hover_enrichment_title blue">%s:</h5>', Inflector::humanize(h($enrichment_type)));
    if (isset($enrichment_values['error'])) {
        echo '<div style="padding: 2px;" class="red">' . __('Error: %s', h($enrichment_values['error']))  . '</div>';
        continue;
    }
    if (empty($enrichment_values)) {
        echo '<div style="padding: 2px;" class="red">' . __('Empty results') . '</div>';
        continue;
    }
    if (!empty($enrichment_values['Object'])) {
        foreach ($enrichment_values['Object'] as $object) {
            echo '<h6 class="bold blue">' . __('Object: %s', h($object['name'])) . '</h6>';
            echo '<table class="table table-striped table-condensed">';
            foreach ($object['Attribute'] as $object_attribute) {
                echo '<tr><th style="width: 15em">' . h($object_attribute['object_relation']) . '</th><td>' . $formatValue($object_attribute) . '</td></tr>';
            }
            echo '</table>';
        }
        unset($enrichment_values['Object']);
    }
    if (!empty($enrichment_values['Attribute'])) {
        echo '<h6 class="bold blue">' . __('Attributes') . '</h6>';
        echo '<table class="table table-striped table-condensed">';
        foreach ($enrichment_values['Attribute'] as $attribute) {
            echo '<tr><th style="width: 15em">' . h($attribute['type']). '</th><td>' . $formatValue($attribute) . '</td></tr>';
        }
        echo '</table>';
        unset($enrichment_values['Attribute']);
    }
    foreach ($enrichment_values as $attributes) {
        foreach ($attributes as $attribute) {
            echo '<div style="padding: 2px;">';
            if (is_array($attribute)) {
                foreach ($attribute as $attribute_name => $attribute_value) {
                    if (!is_numeric($attribute_name)) {
                        echo '<strong>' . h($attribute_name) . ':</strong> ';
                    }
                    echo ' ' . h($attribute_value);
                }
            } else {
                echo h($attribute);
            }
            echo '</div>';
        }
    }
}
?>
</div>
