<?php

$isEdit = (($action ?? 'add') === 'edit');
$isFork = !$isEdit && isset($forkedClusterMeta);
$cluster = $this->request->data['GalaxyCluster'] ?? [];

$currentDistribution = isset($cluster['distribution'])
    ? (int)$cluster['distribution']
    : (int)($initialDistribution ?? 0);

/* edit() posts to itself; a fork keeps its named parameter so that a rejected
 * save re-renders with the forked cluster still in hand. */
if ($isEdit) {
    $formUrl = $baseurl . '/galaxy_clusters/edit/' . h($clusterId ?? $id ?? '');
} else {
    $formUrl = $baseurl . '/galaxy_clusters/add/' . h($galaxy_id);
    if ($isFork && !empty($this->request->params['named']['forkUuid'])) {
        $formUrl .= '/forkUuid:' . h($this->request->params['named']['forkUuid']);
    }
}

echo $this->Form->create('GalaxyCluster', [
    'id' => 'galaxyClusterForm',
    'url' => $formUrl,
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => __('Galaxy Clusters'),
    'title' => $isEdit
        ? __('Edit Galaxy Cluster')
        : ($isFork ? __('Fork Galaxy Cluster') : __('Add Galaxy Cluster')),
    'description' => $isFork
        ? __('A fork is a cluster of your own that keeps a link to the one it extends.')
        : __('A cluster is one entry of a galaxy — an actor, a tool, a technique — that can be attached to events and attributes as a tag.'),
    'titleIcon' => $isFork ? 'fas fa-code-branch' : null,
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4 px-2">

        <?php
        echo $this->Form->hidden('galaxy_id', ['value' => $galaxy_id]);
        echo $this->Form->hidden('extends_uuid');
        echo $this->Form->hidden('extends_version');
        if ($isEdit) {
            echo $this->Form->hidden('id');
            echo $this->Form->hidden('uuid');
        }
        ?>

        <?php if ($isFork): ?>
            <!-- ── FORK SOURCE ─────────────────────────────────── -->
            <div class="d-flex align-items-center gap-3 rounded p-3"
                 style="background:rgba(var(--bs-galaxy-rgb), .06);
                        border:1px solid rgba(var(--bs-galaxy-rgb), .25);">
                <i class="fas fa-code-branch text-galaxy"></i>
                <div class="flex-grow-1">
                    <div class="fw-semibold" style="font-size:.85rem;">
                        <?= h($forkedClusterMeta['value'] ?? '') ?>
                    </div>
                    <div class="text-muted" style="font-size:.75rem;">
                        <?= __('Forked at version %s', h($forkedClusterMeta['version'] ?? '?')) ?> ·
                        <code><?= h($forkedClusterMeta['uuid'] ?? '') ?></code>
                    </div>
                </div>
                <?php if (!empty($forkedCluster['GalaxyCluster']['id'])): ?>
                    <a class="btn btn-sm btn-outline-galaxy"
                       href="<?= $baseurl ?>/galaxy_clusters/view/<?= h($forkedCluster['GalaxyCluster']['id']) ?>"
                       target="_blank" rel="noopener">
                        <i class="fas fa-eye me-1"></i><?= __('View') ?>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'galaxy',
                'label' => __('Name'),
                'required' => true,
            ]) ?>
            <?= $this->Form->text('value', [
                'id' => 'GalaxyClusterValue',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none;',
                'placeholder' => __('e.g. APT28'),
                'autocomplete' => 'off',
                'data-om-required' => 'true',
            ]) ?>
            <div class="invalid-feedback">
                <?= __('A name is required.') ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('What the cluster is known as — this is the value the tag carries.'),
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'galaxy',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'style' => 'border-color:#d8dde3;',
                'rows' => 3,
                'placeholder' => __('Briefly describe what this cluster stands for…'),
            ]) ?>
        </div>

        <!-- ── SOURCE / AUTHORS ────────────────────────────────── -->
        <div class="row g-3">
            <div class="col-12 col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'galaxy',
                    'label' => __('Source'),
                ]) ?>
                <?= $this->Form->text('source', [
                    'class' => 'form-control',
                    'style' => 'border-color:#d8dde3;',
                    'placeholder' => __('e.g. the report this cluster comes from'),
                ]) ?>
            </div>
            <div class="col-12 col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'galaxy',
                    'label' => __('Authors'),
                ]) ?>
                <?= $this->Form->text('authors', [
                    'id' => 'GalaxyClusterAuthors',
                    'class' => 'form-control',
                    'style' => 'border-color:#d8dde3;',
                    'placeholder' => __('e.g. Jane Doe, John Doe'),
                ]) ?>
            </div>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'accent' => 'galaxy',
                'levels' => $distributionLevels,
                'value' => $currentDistribution,
                'sharingGroups' => $sharingGroups,
                'showSg' => true,
                'id' => 'GalaxyClusterDistribution',
                'sgId' => 'GalaxyClusterSharingGroupId',
                'sgEmpty' => empty($sharingGroups)
                    ? __('No sharing group available')
                    : false,
            ]) ?>
        </div>

        <!-- ── ELEMENTS ────────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'elements',
                'accent' => 'galaxy',
                'label' => __('Cluster Elements'),
                'shape' => 'array',
                'id' => 'GalaxyClusterElements',
                'rows' => 5,
                'minHeight' => '130px',
                'placeholder' => '[{"key": "synonyms", "value": "Fancy Bear"}]',
                'hint' => __('Optional — a list of key/value pairs describing the cluster.'),
            ]) ?>
        </div>

    </div>

    <?php
    $footerMeta = [];
    if ($isEdit) {
        if (!empty($id)) {
            $footerMeta[] = ['label' => __('Cluster'), 'id' => $id];
        }
        if (!empty($cluster['uuid'])) {
            $footerMeta[] = ['label' => __('UUID'), 'value' => $cluster['uuid'], 'mono' => true];
        }
    }
    /* Only a fork overrides the glyph — leaving the key out lets the footer
     * pick its own save / add one. */
    $submit = [
        'label' => $isEdit
            ? __('Save Changes')
            : ($isFork ? __('Fork Cluster') : __('Add Cluster')),
    ];
    if ($isFork) {
        $submit['icon'] = 'fas fa-code-branch';
    }
    echo $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'galaxy',
        'isEdit' => $isEdit,
        'meta' => $footerMeta,
        'hint' => __('The cluster is saved unpublished — publish it when it is ready to travel.'),
        'submit' => $submit,
    ]);
    ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('galaxyClusterForm');
    if (!form) {
        return;
    }

    var authorsEl = document.getElementById('GalaxyClusterAuthors');

    var required = Array.prototype.slice.call(
        form.querySelectorAll('[data-om-required]')
    );

    var flag = function (el, invalid) {
        el.classList.toggle('is-invalid', invalid);
    };

    required.forEach(function (el) {
        el.addEventListener('input', function () {
            if (String(el.value || '').trim()) {
                flag(el, false);
            }
        });
    });

    /* The elements are a json_field, which reports and refuses a broken
       document on its own. Authors reach the controller as JSON too, but they
       also accept a comma separated list, so only a value that looks like JSON
       is parsed — which is not the json_field contract. */
    var checkAuthors = function () {
        if (!authorsEl) {
            return true;
        }
        var raw = String(authorsEl.value || '').trim();
        if (raw.charAt(0) !== '[' && raw.charAt(0) !== '{') {
            flag(authorsEl, false);
            return true;
        }
        try {
            JSON.parse(raw);
        } catch (e) {
            flag(authorsEl, true);
            return false;
        }
        flag(authorsEl, false);
        return true;
    };

    if (authorsEl) {
        authorsEl.addEventListener('input', function () {
            if (authorsEl.classList.contains('is-invalid')) {
                checkAuthors();
            }
        });
    }

    form.addEventListener('submit', function (e) {
        var firstInvalid = null;
        required.forEach(function (el) {
            var empty = !String(el.value || '').trim();
            flag(el, empty);
            if (empty && !firstInvalid) {
                firstInvalid = el;
            }
        });
        if (!checkAuthors() && !firstInvalid) {
            firstInvalid = authorsEl;
        }
        if (firstInvalid) {
            e.preventDefault();
            e.stopPropagation();
            firstInvalid.focus();
        }
    });
})();
</script>
