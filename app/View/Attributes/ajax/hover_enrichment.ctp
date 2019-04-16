<div style="overflow-y:auto;max-height:75vh">
    <?php
        foreach ($results as $enrichment_type => $enrichment_values):
            echo sprintf('<h5><span class="hover_enrichment_title blue">%s</span>:</h5>', Inflector::humanize(h($enrichment_type)));
            if (isset($enrichment_values['Object'])) {
                echo '<h6><span class="bold blue">Objects</span></h6>';
                foreach ($enrichment_values['Object'] as $object) {
                    echo '<span class="object_name bold blue">' . h($object['name']) . '</span><br />';
                    foreach ($object['Attribute'] as $object_attribute) {
                        echo '<div style="padding: 2px;"><pre class="object_attribute">';
                        echo '<span class="attribute_object_relation bold blue">' . h($object_attribute['object_relation']) . '</span>';
                        echo ': <span class="attribute_value red">' . h($object_attribute['value']) . '</span></pre></div>';
                    }
                }
                unset($enrichment_values['Object']);
            }
            if (isset($enrichment_values['Attribute'])) {
                echo '<h6><span class="bold blue">Attributes</span><br />';
                foreach ($enrichment_values['Attribute'] as $attribute) {
                    echo '<div style="padding: 2px;"><pre class="attribute">';
                    echo '<span class="attribute_type bold blue">' . h($attribute['type']) . '</span>';
                    echo ': <span class="attribute_value red">' . h($attribute['value']) . '</span></pre></div>';
                }
                unset($enrichment_values['Attribute']);
            }
            foreach ($enrichment_values as $attributes):
                foreach ($attributes as $attribute):
                    echo '<div style="padding: 2px;">';
                    if (is_array($attribute)) {
                        foreach ($attribute as $attribute_name => $attribute_value) {
                            if (!is_numeric($attribute_name)) {
                                echo '<span class="hover_enrichment_text blue">' . h($attribute_name) . ':</span>';
                            }
                            echo '<span><pre class="hover_enrichment_text red">' . h($attribute_value) . '</pre></span>';
                        }
                    } else {
                        echo '<span><pre class="hover_enrichment_text red ">' . h($attribute) . '</pre></span>';
                    }
                    echo '</div>';
                endforeach;
            endforeach;
            echo "<br/>";
        endforeach;
    ?>
</div>
