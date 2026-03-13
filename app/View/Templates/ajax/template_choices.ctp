<div class="popover_choice">
    <legend><?php echo __('Choose element type'); ?></legend>
    <div class="popover_choice_main" id="popover_choice_main">
        <?php foreach ($templates as $k => $template): ?>
            <a href="<?= $this->Html->url([
                            'controller' => 'templates',
                            'action' => 'populateEventFromTemplate',
                            $template['Template']['id'],
                            $id
                        ]); ?>"
                class="templateChoiceButton"
                style="width:100%; display:block;text-decoration:none;"
                role="button"
                tabindex="0"
                aria-label="<?= h($template['Template']['description']); ?>"
                title="<?= h($template['Template']['description']); ?>">
                <div style="float:left;">
                    <?= $this->OrgImg->getOrgImg([
                        'name' => $template['Template']['org'],
                        'size' => 24
                    ], false, true); ?>
                </div>
                <div>
                    <span style="position:relative;left:-12px;">
                        <?= h($template['Template']['name']); ?>&nbsp;
                    </span>
                </div>
            </a>
        <?php endforeach; ?>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" title="<?php echo __('Cancel'); ?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel'); ?></div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>