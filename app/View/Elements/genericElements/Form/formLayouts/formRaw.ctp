<?php if (!empty($data['description']) || !empty($data['descriptionHtml'])) : ?>
    <div class="pb-3 fw-light">
        <?= !empty($data['descriptionHtml']) ? $data['descriptionHtml'] : h($data['description']) ?>
    </div>
<?php endif; ?>
<?= $ajaxFlashMessage ?>
<?= $formCreate ?>
<?= $fieldsString ?>

<?php if (!empty($metaTemplateString)) : ?>
    <?=
    $this->Bootstrap->accordion(
        [
            'class' => 'mb-3'
        ],
        [
            [
                'open' => true,
                'header' => [
                    'text' => __('Meta fields')
                ],
                'body' => $metaTemplateString,
            ],
        ]
    );
    ?>
<?php endif; ?>
<?= $formEnd; ?>