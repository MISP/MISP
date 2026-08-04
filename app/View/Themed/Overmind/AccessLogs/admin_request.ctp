<div class="p-3 border-bottom d-flex align-items-center gap-2">
    <i class="far fa-file-alt text-primary"></i>
    <span class="fw-bold"><?= __('HTTP request') ?></span>
    <button type="button" class="btn-close ms-auto" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
</div>
<div class="p-3">
    <pre class="bg-body-secondary border rounded-2 p-3 mb-0 overflow-auto"
         style="max-height:65vh;white-space:pre-wrap;word-wrap:break-word;"><?= $request ?></pre>
</div>
