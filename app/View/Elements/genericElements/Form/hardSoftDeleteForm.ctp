<?php
    /*
     * Form proposing different delete methods
     * 
     * - title: Title of the form
     * - modelName: The model of the deleted element
     * - value: The value being deleted
     * - id: the ID of the value being deleted
     * - additionaMessage: array of message to be inserted
     * - softDeleteURL: The optional soft delete URL to POST to
     * - hardDeleteURL: The hard delete URL to POST to
     * - doNotShowHelp: If help text for soft/hard deleting should not be shown
     * 
     */
?>
<div class="confirmation">
    <? if (!empty($title)): ?>
        <legend><?= h($title) ?></legend>
    <? endif; ?>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <h6><?= __('Are you sure you want to delete %s %s (%s)?', h($modelName), sprintf('<i style="font-size: larger">%s</i>', h($value)), h($id)) ?></h6>
    <ul>
        <?php if (!isset($doNotShowHelp) || !$doNotShowHelp ): ?>
            <li><?= sprintf(__('%s a %s propagates the deletion to other instances and lets you restore it in the future'), sprintf('<strong class="blue">%s</strong>', __('Soft-deleting')), h($modelName)) ?></li>
            <li><?= sprintf(__('%s a %s permanentaly deletes it'), sprintf('<strong class="red">%s</strong>', __('Hard-deleting')), h($modelName)) ?></li>
        <?php endif; ?>
    </ul>
    <?php if (!empty($additionalMessage)): ?>
        <ul>
            <li><?= implode('</li><li>', $additionalMessage) ?></li>
        </ul>
    <?php endif; ?>
    <div style="display: flex">
        <?php
            if (!empty($softDeleteURL)) {
                echo $this->Form->postButton(
                    '<i class="' . $this->FontAwesome->getClass('trash') . ' fa-trash"></i> ' . __('Soft-delete'),
                    $softDeleteURL,
                    array('class' => 'btn btn-primary')
                );
                echo '<span style="width: 0.5em";></span>';
            }
            $hardDeleteText = !empty($softDeleteURL) ? __('Hard-delete') : __('Delete');
            echo $this->Form->postButton(
                '<i class="' . $this->FontAwesome->getClass('ban') . ' fa-ban"></i> ' . $hardDeleteText,
                $hardDeleteURL,
                array('class' => 'btn btn-danger')
            );
        ?>
        <button type="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" style="margin-left: auto; height: fit-content;" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
    </div>
</div>
<?php
    echo $this->Form->end();
?>
</div>