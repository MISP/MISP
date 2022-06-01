<div>
    <h3 class="bold">
        <i class="bold fa-fw <?= $this->FontAwesome->getClass('hourglass-start') ?>" style="font-size: larger;" title="<?= __('Blocking execution path') ?>"></i>
        <?= __('Blocking Execution order') ?>
    </h3>
    <?php if (empty($trigger['GroupedWorkflows']['blocking'])) : ?>
        <div class="alert alert-info">
            <strong><?= __('No blocking workflows!') ?></strong>
            <div><?= __('The trigger <strong>%s</strong> has no blocking workflows listening to it.', h($trigger['name'])) ?></div>
        </div>
    <?php else : ?>
        <div id="container-unsaved-change" class="alert alert-info hidden">
            <strong><?= __('Unsaved changes!') ?></strong>
            <div><?= __('The execution order has changed and hasn\'t been saved.') ?></div>
            <div style="margin-top: 1em;">
                <button id="btn-save" class="btn btn-success">
                    <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                    <span class="fa-fw fas fa-spin fa-spinner loading-icon hidden"></span>
                </button>
                <button id="btn-reset" class="btn btn-default"><?= __('Reset order') ?></button>
            </div>
        </div>
        <div style="margin: 2em 1em;">
            <ul id="workflows-sortable" class="unstyled">
                <?php foreach ($trigger['GroupedWorkflows']['blocking'] as $i => $workflow) : ?>
                    <?= $this->element('Workflows/executionOrderWidgetLI', ['workflow' => $workflow]) ?>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
</div>

<?php
echo $this->element('genericElements/assetLoader', [
    'js' => ['jquery-ui'],
]);
?>

<script>
    $(function() {
        $(document).ready(function() {
            initialHtmlState = $('#workflows-sortable').html()
            initialState = collectWorklowOrder()
            initSortable()
            $('#btn-reset').click(function() {
                resetOrder(this)
            })
            $('#btn-save').click(function() {
                saveOrder(this)
            })
        })

        var initialHtmlState = false
        var initialState = false

        function initSortable() {
            $('#workflows-sortable').sortable({
                cursor: 'grabbing',
                scroll: false,
                update: function(event, ui) {
                    toggleUnsaveWarning()
                }
            })
        }

        function resetOrder(clicked) {
            $('#workflows-sortable').html(initialHtmlState)
            initSortable()
            toggleUnsaveWarning()
        }

        function saveOrder(clicked) {
            var workflow_order = collectWorklowOrder()
            var url = "<?= $baseurl . '/workflows/rearrangeExecutionOrder/' . h($trigger['id']) ?>"
            fetchFormDataAjax(url, function(formHTML) {
                var $tmpForm = $(formHTML).find('form')
                var formUrl = $tmpForm.attr('action')
                $tmpForm.find('[name="data[Workflow][workflow_order]"]').val(JSON.stringify(workflow_order))

                $.ajax({
                    data: $tmpForm.serialize(),
                    beforeSend: function() {
                        toggleLoadingInSaveButton(true)
                    },
                    success: function(result, textStatus) {
                        if (result) {
                            showMessage('success', result.message);
                            if (result.data !== undefined) {
                                initialState = result.data
                            }
                        }
                    },
                    error: function(jqXHR, textStatus, errorThrown) {
                        showMessage('fail', textStatus + ': ' + errorThrown);
                    },
                    complete: function() {
                        toggleLoadingInSaveButton(false)
                        window.location.reload()
                    },
                    type: "post",
                    url: formUrl
                })
            })
        }

        function collectWorklowOrder() {
            var order = []
            $('#workflows-sortable > li').each(function() {
                var $li = $(this)
                order.push($li.data('workflowid'))
            })
            return order;
        }

        function toggleUnsaveWarning() {
            if (JSON.stringify(initialState) !== JSON.stringify(collectWorklowOrder())) {
                $('#container-unsaved-change').show()
            } else {
                $('#container-unsaved-change').hide()
            }
        }

        function toggleLoadingInSaveButton(saving) {
            var $saveButton = $('#btn-save')
            $saveButton.prop('disabled', saving)
            if (saving) {
                $saveButton.find('.loading-icon').show();
            } else {
                $saveButton.find('.loading-icon').hide();
            }
        }
    })
</script>

<style>
    #workflows-sortable > li {
        display: flex;
        width: 30%;
        min-width: 350px;
        border: 1px solid #ddd;
        border-radius: 3px;
        padding: 0.25em 0.5em;
        margin-bottom: 0.5em;
        cursor: grab;
        font-size: larger;
    }

    #workflows-sortable > li > i.fas {
        margin-right: 10px;
        align-self: center;
    }

    #workflows-sortable > li > div {
        flex-grow: 1;
        overflow: hidden;
    }
</style>