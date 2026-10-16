<div class="row g-3 mb-3 eo-row">
    <div class="col-12 col-xl-7">
        <?= $this->element('Events/View/event_attachments', ['data' => $data]) ?>
    </div>
    <div class="col-12 col-xl-5">
        <?= $this->element('Events/View/overview_assessment', ['data' => $data]) ?>
    </div>
</div>
