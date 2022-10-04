<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= h($title) ?></h3>
    </div>
    <div class="modal-body modal-body-long">
        <p><?= h($description) ?></p>
        <?php
            $randomNumber = rand();
            echo $this->Form->create($model, ['id' => $randomNumber . 'Form']);
            echo $this->Form->input('relationship_type', [
                'type' => 'select',
                'options' => $options
            ]);
            echo $this->Form->end();
        ?>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn btn-primary button-execute" onclick="$('#<?= $randomNumber . 'Form' ?>').submit();"><?= __('Submit') ?></button>
        <button type="button" class="btn btn-secondary cancel-button" data-dismiss="modal"><?= __('Cancel') ?></button>
    </div>
</div>
<script type="text/javascript">
    $(document).keydown(function(e) {
        if(e.which === 13 && e.ctrlKey) {
            $('.button-execute').click();
        }
    });
</script>
