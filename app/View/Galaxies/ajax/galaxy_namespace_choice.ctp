<div class="popover_choice  select_galaxy_namespace_source">
    <legend><?php echo __('Select Galaxy Namespace Source');?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td role="button" tabindex="0" aria-label="<?php echo __('All namespaces');?>" title="<?php echo __('All namespaces');?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($target_id) . '/' . h($target_type); ?>/0', 'galaxies', 'selectGalaxy');"><?php echo __('All Namespaces');?></td>
            </tr>
        <?php foreach ($namespaces as $namespace): ?>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td role="button" tabindex="0" aria-label="<?php echo h($namespace); ?>" title="<?php echo h($namespace); ?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($target_id) . "/" . h($target_type); ?>/<?php echo h($namespace)?>', 'galaxies', 'selectGalaxy');"><?php echo h($namespace); ?></td>
            </tr>
        <?php endforeach; ?>
        </table>
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
