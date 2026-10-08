<?php

$scopes = ['attribute', 'object', 'tag', 'galaxymatrix'];
$scopesHtml = '<code>' . implode('</code> <code>', $scopes) . '</code>';

$shortcuts = [
    ['keys' => ['Ctrl', 'Space'], 'label' => __('Suggest the event\'s attributes, objects, tags and galaxies')],
    ['keys' => ['Ctrl', 'M'],     'label' => __('Insert a MISP element reference')],
    ['keys' => ['Ctrl', 'B'],     'label' => __('Makes text bold')],
    ['keys' => ['Ctrl', 'I'],     'label' => __('Makes text italic')],
    ['keys' => ['Ctrl', 'H'],     'label' => __('Makes the line a heading, one level per press')],
    ['keys' => ['Ctrl', 'S'],     'label' => __('Save the report')],
];

$examples = [
    'element'  => ['@[attribute](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)',
                   '@[object](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)',
                   '@[galaxymatrix](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)'],
    'picture'  => ['@![attribute](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)'],
    'tag'      => ['@[tag](tlp:green)', '@[tag](misp-galaxy:threat-actor="APT 29")'],
    'variable' => ['{{banner_tlp_green}}', '{{my_company_logo}}'],
];

$list = function (array $items) {
    $html = '<ul class="small">';
    foreach ($items as $item) {
        $html .= '<li><code>' . h($item) . '</code></li>';
    }
    return $html . '</ul>';
};
?>

<div class="modal fade"
     id="er-help-modal"
     tabindex="-1"
     aria-labelledby="er-help-modal-label"
     aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">

            <?= $this->element('genericElementsBS5/Forms/modal_header', [
                'accent' => 'report',
                'eyebrow' => __('Event Reports'),
                'title' => __('Markdown help'),
                'titleId' => 'er-help-modal-label',
                'titleIcon' => 'fas fa-circle-question',
                'description' => __('What this editor understands beyond plain markdown, and how to write it.'),
                'close' => true,
            ]) ?>

            <div class="modal-body ov-help-body">

                <ul class="nav nav-tabs mb-3" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" data-bs-toggle="tab"
                                data-bs-target="#er-help-format" type="button" role="tab">
                            <i class="fab fa-markdown me-1"></i><?= __('Markdown format') ?>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-bs-toggle="tab"
                                data-bs-target="#er-help-shortcuts" type="button" role="tab">
                            <i class="fas fa-keyboard me-1"></i><?= __('Editor shortcuts') ?>
                        </button>
                    </li>
                </ul>

                <div class="tab-content">

                    <!-- ─── MARKDOWN FORMAT ───────────────────────────── -->
                    <div class="tab-pane fade show active" id="er-help-format" role="tabpanel">

                        <p class="small">
                            <?= __('The supported markdown format is similar to %s with some differences:',
                                '<a href="https://github.github.com/gfm/" target="_blank" rel="noopener">GFM</a>') ?>
                        </p>
                        <ul class="small">
                            <li><?= __('No html support, typographer & autolinker') ?></li>
                            <li><?= __('An additional syntax to reference MISP Elements') ?></li>
                        </ul>

                        <h6 class="fw-bold"><?= __('MISP elements') ?></h6>
                        <p class="small mb-2">
                            <?= __('So that a report stays readable without hardcoding an element\'s value or ID, MISP elements such as attributes and objects are referenced with a syntax of their own:') ?>
                        </p>
                        <p class="text-center"><code>@[scope](UUID)</code></p>
                        <ul class="small">
                            <li><b>scope</b> — <?= __('one of %s', $scopesHtml) ?></li>
                            <li><b>UUID</b> — <?= __('the UUID of the element, the tag being the one exception') ?></li>
                        </ul>
                        <?= $list($examples['element']) ?>

                        <h6 class="fw-bold"><?= __('Pictures from attachment-type attributes') ?></h6>
                        <ul class="small">
                            <li><?= __('A leading %s shows the picture rather than the attribute', '<code>!</code>') ?></li>
                            <li><?= __('The scope is always %s — only an attribute carries a file', '<code>attribute</code>') ?></li>
                        </ul>
                        <?= $list($examples['picture']) ?>

                        <h6 class="fw-bold"><?= __('Tags') ?></h6>
                        <ul class="small">
                            <li><?= __('The scope is always %s', '<code>tag</code>') ?></li>
                            <li><?= __('A tag has no UUID, so it is named instead') ?></li>
                        </ul>
                        <?= $list($examples['tag']) ?>

                        <h6 class="fw-bold"><?= __('Event\'s Galaxy matrixes') ?></h6>
                        <ul class="small">
                            <li><?= __('The scope is always %s', '<code>galaxymatrix</code>') ?></li>
                            <li><?= __('The galaxy is named for the whole event the report belongs to') ?></li>
                        </ul>

                        <h6 class="fw-bold"><?= __('Template Variables') ?></h6>
                        <ul class="small">
                            <li><?= __('Variables are written in the Handlebars notation') ?></li>
                            <li><?= __('Each one is replaced by whatever the instance defines for that name, or by nothing when it is undefined.') ?></li>
                        </ul>
                        <?= $list($examples['variable']) ?>
                        <p class="small mb-0">
                            <a href="<?= h($baseurl . '/eventReportTemplateVariables/index') ?>" target="_blank">
                                <i class="fas fa-screwdriver me-1"></i><?= __('Configure template variables') ?>
                            </a>
                        </p>
                    </div>

                    <!-- ─── SHORTCUTS ─────────────────────────────────── -->
                    <div class="tab-pane fade" id="er-help-shortcuts" role="tabpanel">
                        <table class="table table-sm align-middle mb-0">
                            <thead>
                                <tr>
                                    <th style="width:12rem;"><?= __('Command') ?></th>
                                    <th><?= __('Action') ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($shortcuts as $shortcut): ?>
                                    <tr>
                                        <td class="text-nowrap">
                                            <?php foreach ($shortcut['keys'] as $i => $key): ?>
                                                <?= $i ? ' + ' : '' ?><kbd><?= h($key) ?></kbd>
                                            <?php endforeach; ?>
                                        </td>
                                        <td class="small"><?= h($shortcut['label']) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        <p class="small text-muted mt-3 mb-0">
                            <i class="fas fa-lightbulb me-1"></i>
                            <?= __('The suggestion list also opens on its own while writing inside %s, and picking a scope there moves straight on to the elements of that scope.', '<code>@[…](…)</code>') ?>
                        </p>
                    </div>

                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                    <?= __('Close') ?>
                </button>
            </div>

        </div>
    </div>
</div>
