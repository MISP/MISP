<div class="confirmation">
    <?php
    echo $this->Form->create('Correlation', ['style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/correlations/switchEngine/' . urlencode($engine)]);
    $message = __('Switch Engine');
    $buttonTitle = __('Switch');
    ?>
    <legend><?= $message ?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <?php
            echo '<p>' . __('Are you sure you want to switch to the given correlation engine (' . h($engine) . ')? If so, it is highly recommended that you recorrelate afterwards.') . '</p>';
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
