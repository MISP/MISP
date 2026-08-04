
<div class="accordion" id="accordion">
<?php
    foreach ($finalSettings as $subGroup => &$settings) {
        echo sprintf(
            '<div class="accordion-group"><div class="accordion-heading">%s</div><div id=collapse_%s class="accordion-body collapse">%s</div></div>',
            sprintf(
                '<a class="accordion-toggle" data-toggle="collapse" data-parent="accordion" href="#collapse_%s">%s</a>',
                h($subGroup),
                h($subGroup)
            ),
            h($subGroup),
            sprintf(
                '<div class="accordion-inner">%s</div>',
                $this->element('healthElements/settings_table', array('settings' => $settings, 'subGroup' => $subGroup))
            )
        );
    }
?>
</div>
