<div style="overflow-y:auto;max-height:75vh">
    <?php
        foreach ($results as $enrichment_type => $enrichment_values):
            echo sprintf('<span class="hover_enrichment_title blue">%s</span>: <br />', Inflector::humanize(h($enrichment_type)));

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
