<?php
    if ($ajax) {
?>
        <div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
                <h3 id="genericModalLabel"><?= __('Authkey created'); ?></h3>
            </div>
            <div class="modal-body modal-body-long">
                <p><?= __('Please make sure that you note down the authkey below, this is the only time the authkey is shown in plain text, so make sure you save it. If you lose the key, simply remove the entry and generate a new one.'); ?></p>
                <p><?=__('MISP will use the first and the last 4 characters for identification purposes.')?></p>
                <pre class="quickSelect"><?= h($entity['AuthKey']['authkey_raw']) ?></pre>
            </div>
            <div class="modal-footer">
                <a href="<?= $referer ?>" class="btn btn-primary"><?= __('I have noted down my key, take me back now') ?></a>
            </div>
        </div>
<?php
    } else {
?>
        <h4><?= __('Authkey created'); ?></h4>
        <p><?= __('Please make sure that you note down the authkey below, this is the only time the authkey is shown in plain text, so make sure you save it. If you lose the key, simply remove the entry and generate a new one.'); ?></p>
        <p><?=__('MISP will use the first and the last 4 characters for identification purposes.')?></p>
        <pre class="quickSelect"><?= h($entity['AuthKey']['authkey_raw']) ?></pre>
        <a href="<?= $referer ?>" class="btn btn-primary"><?= __('I have noted down my key, take me back now') ?></a>
<?php
    }
?>
