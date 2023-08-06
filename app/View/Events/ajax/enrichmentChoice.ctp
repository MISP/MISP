<?php
    if (empty($type)) {
        $type = 'Enrichment';
    }
?>
<div class="popover_choice">
    <legend><?php echo __('Choose the enrichment module that you wish to use for the expansion'); ?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <div style="width:100%;">
        <?php
            usort($modules, function ($a, $b) {
                return strcmp(strtolower($a['name']), strtolower($b['name']));
            });
            foreach ($modules as $k => $module) {
                echo sprintf(
                    '<div style="%s" class="templateChoiceButton useCursorPointer" onClick="%s" title="%s" role="button" tabindex="0" aria-label="%s">%s</div>',
                    'border-bottom:1px solid black; text-align:center;width:100%;',
                    sprintf(
                        "window.location='%s/events/queryEnrichment/%s';",
                        $baseurl,
                        implode('/', array(h($id), h($module['name']), h($type), h($model)))
                    ),
                    h($module['description']),
                    __('Enrich using the %s module', h($module['name'])),
                    sprintf(
                        '<span class="bold">%s</span>: %s',
                        h($module['name']),
                        h($module['description'])
                    )
                );
            }
        ?>
        </div>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
