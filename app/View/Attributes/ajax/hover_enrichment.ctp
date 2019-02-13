<div style="overflow-y:auto;max-height:75vh">
    <?php
        foreach ($results as &$r):
            foreach ($r as $k => &$v):
                echo sprintf('<span class="bold blue">%s</span>: <br />', Inflector::humanize(h($k)));
                if (is_array($v)) {
                    foreach ($v as $key => $value) {
                        if (!is_numeric($key)) {
                            echo '<div class="blue" style="margin-left:10px;">' . h($key) . ':</div>';
                        }
                        echo '<div class="red" style="margin-left:20px;"><pre class="red" style="border:0px;background-color:transparent;">' . h($value) . '</pre></div>';
                    }
                } else {
                    echo '<div style="margin-left:20px;"><pre class="red" style="border:0px;background-color:transparent;">' . h($v) . '</pre></div>';
                }
            endforeach;
        endforeach;
    ?>
</div>
