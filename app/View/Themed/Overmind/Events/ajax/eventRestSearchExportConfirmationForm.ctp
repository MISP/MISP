<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto">
        <?php
            echo $this->Form->create('Event', [
                'id' => 'PromptForm',
                'url' => $baseurl . '/events/restSearchExport',
                'class' => 'm-0',
                'data-idlist' => json_encode($idList)
            ]);
        ?>

        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?php echo __('Export Events'); ?>
            </h4>
        </div>

        <div class="card-body">
            <p class="mb-3 text-muted">
                <?php echo __('Export the selected events into the selected format'); ?>
            </p>

            <div class="mb-4">
                <?php
                    echo $this->Form->input('returnFormat', [
                        'label' => __('Export Format'),
                        'class' => 'form-select',
                        'type' => 'select',
                        'options' => $exportFormats,
                        'id' => 'EventReturnFormat'
                    ]);
                ?>
            </div>

            <div class="d-flex justify-content-between align-items-center">
                <button 
                    type="button"
                    class="btn btn-primary"
                    title="<?php echo __('Export');?>"
                    aria-label="<?php echo __('Export');?>"
                    id = "PromptYesButton"
                    onclick="redirectToExportResult();">
                    <?php echo __('Export');?>
                </button>

                <button 
                    type="button"
                    class="btn btn-outline-secondary"
                    title="<?php echo __('Cancel');?>"
                    aria-label="<?php echo __('Cancel');?>"
                    id="PromptNoButton"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?php echo __('Cancel');?>
                </button>
            </div>

            <?php echo $this->Form->end(); ?>
        </div>
    </div>
</div>


<script>
    function redirectToExportResult() {
        var idListStr = '<?php echo json_encode($idList); ?>';
        var returnFormat = $('#EventReturnFormat').val();
        if (returnFormat) {
            window.location = '<?php echo $baseurl; ?>/events/restSearchExport/' + idListStr + '/' + returnFormat;
        }
    }
</script>