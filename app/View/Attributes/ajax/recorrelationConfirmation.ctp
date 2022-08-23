<div class="confirmation">
    <?php
    echo $this->Form->create('Attribute', ['style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/attributes/generateCorrelation']);
    $message = __('Recorrelate instance');
    $buttonTitle = __('Recorrelate');
    ?>
    <legend><?= $message ?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <?php
            echo '<p>' . __('Are you sure you wish to start a recorrelation for the currently active correlation engine?') . '</p>';
            echo '<p>' . __('Depending on the system and the amount of attributes, this might take a long time.') . '</p>';
        ?>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <button role="button" tabindex="0" aria-label="<?= $buttonTitle ?>" title="<?= $buttonTitle ?>" id="PromptYesButton" class="btn btn-primary"><?= __('Yes') ?></button>
                </td>
                <td style="width:100%;"></td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="<?= __('Cancel');?>" title="<?= __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onclick="cancelPrompt()"><?= __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?= $this->Form->end(); ?>
</div>
