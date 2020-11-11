<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= __('Delete %s', Inflector::singularize(Inflector::humanize($this->params['controller']))) ?></h3>
    </div>
    <div class="modal-body modal-body-long">
        <p><?= __('Are you sure you want to delete %s #%s?', h(Inflector::singularize($this->params['controller'])), h($id)) ?></p>
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
</div>
<script type="text/javascript">
    $(document).keydown(function(e) {
        if(e.which === 13 && e.ctrlKey) {
            $('.button-execute').click();
        }
    });
</script>
