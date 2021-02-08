<?php
$title = Inflector::singularize(Inflector::humanize(Inflector::underscore($this->params['controller'])));
?>
<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= __('Delete %s', h($title)) ?></h3>
    </div>
    <?php if ($validationError): ?>
        <div class="modal-body modal-body-long">
            <p><?= h($validationError) ?></p>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary cancel-button" data-dismiss="modal"><?= __('Cancel') ?></button>
        </div>
    <?php else: ?>
    <div class="modal-body modal-body-long">
        <p><?= __('Are you sure you want to delete %s #%s?', h($title), h($id)) ?></p>
    </div>
    <div class="modal-footer">
        <?= $this->Form->postLink(
            'Delete',
            $this->request->here(),
            ['class' => 'btn btn-primary button-execute']
            )
        ?>
        <button type="button" class="btn btn-secondary cancel-button" data-dismiss="modal"><?= __('Cancel') ?></button>
    </div>
    <?php endif; ?>
</div>
<script type="text/javascript">
    $(document).keydown(function(e) {
        if (e.which === 13 && e.ctrlKey) {
            $('.button-execute').click();
        }
    });
</script>
