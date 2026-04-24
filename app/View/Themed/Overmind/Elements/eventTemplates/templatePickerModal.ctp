<?php
/*
 * Searchable modal for "Add Event → From Template" (PRD §5.2 F2.2).
 * BS5-flavoured counterpart to the default theme's partial.
 * Rendered once on any Overmind page that needs the affordance.
 * Exposes window.openEventTemplatePicker() as the global entry point.
 *
 * On first open, AJAX-fetches /event_templates/index.json and renders
 * the list; subsequent opens reuse the cache for the rest of the page
 * lifetime. The user picks a row → browser navigates to
 * /event_templates/instantiate/{id} which renders the user form.
 */
?>
<div id="et-template-picker-modal" class="modal fade" tabindex="-1"
     aria-labelledby="et-template-picker-title" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="et-template-picker-title">
                    <?= __('Create event from template') ?>
                </h5>
                <button type="button" class="btn-close"
                        data-bs-dismiss="modal" data-dismiss="modal"
                        aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <input type="text" id="et-template-picker-search"
                       class="form-control bg-light mb-2"
                       placeholder="<?= __('Filter by name, description, or organisation…') ?>">
                <div id="et-template-picker-loading" class="text-muted p-2">
                    <?= __('Loading templates…') ?>
                </div>
                <div id="et-template-picker-list"
                     class="border rounded"
                     style="max-height:55vh; overflow-y:auto;"></div>
                <div id="et-template-picker-empty"
                     class="text-muted p-3"
                     style="display:none;">
                    <em><?= __('No event templates visible to you on this instance.') ?></em>
                    <?php if ($this->Acl->canAccess('eventTemplates', 'add')): ?>
                        <a href="<?= h($baseurl . '/event_templates/add') ?>"
                           class="ms-2">
                            <?= __('Build one') ?>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary"
                        data-bs-dismiss="modal" data-dismiss="modal">
                    <?= __('Cancel') ?>
                </button>
            </div>
        </div>
    </div>
</div>

<style>
#et-template-picker-modal .et-tp-item {
    display: block;
    padding: 10px 14px;
    border-bottom: 1px solid #f0f0f0;
    color: #222;
    text-decoration: none;
    line-height: 1.35;
}
#et-template-picker-modal .et-tp-item:hover {
    background: #f0f8ff;
    text-decoration: none;
}
#et-template-picker-modal .et-tp-item-name { font-weight: 600; font-size: 13px; }
#et-template-picker-modal .et-tp-item-meta {
    font-size: 11px;
    color: #999;
    margin-left: 8px;
}
#et-template-picker-modal .et-tp-item-desc {
    color: #666;
    font-size: 12px;
    margin-top: 2px;
    max-height: 3em;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
}
</style>

<script>
(function () {
    var cache = null;
    var cacheLoading = null;
    var BASE = <?= json_encode($baseurl) ?>;

    function load() {
        if (cache !== null) { return Promise.resolve(cache); }
        if (cacheLoading) { return cacheLoading; }
        cacheLoading = fetch(BASE + '/event_templates/index.json', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).then(function (r) {
            if (!r.ok) { throw new Error('HTTP ' + r.status); }
            return r.json();
        }).then(function (rows) {
            cache = (rows || []).map(function (row) {
                var t = row.EventTemplate || {};
                var org = (row.Organisation && row.Organisation.name) || '';
                return {
                    id: parseInt(t.id, 10) || 0,
                    name: t.name || '',
                    description: t.description || '',
                    modified: t.modified || '',
                    orgName: org,
                    active: t.active === true || t.active === 1 || t.active === '1',
                    search: ((t.name || '') + ' ' +
                        (t.description || '') + ' ' +
                        org).toLowerCase()
                };
            }).filter(function (t) { return t.active && t.id > 0; });
            cache.sort(function (a, b) {
                return (b.modified || '').localeCompare(a.modified || '');
            });
            cacheLoading = null;
            return cache;
        }).catch(function (err) {
            cacheLoading = null;
            throw err;
        });
        return cacheLoading;
    }

    function render(items) {
        var $list = document.getElementById('et-template-picker-list');
        var $empty = document.getElementById('et-template-picker-empty');
        if (!$list || !$empty) { return; }
        $list.innerHTML = '';
        if (!items.length) {
            $list.style.display = 'none';
            $empty.style.display = '';
            return;
        }
        $list.style.display = '';
        $empty.style.display = 'none';
        items.forEach(function (t) {
            var $a = document.createElement('a');
            $a.className = 'et-tp-item';
            $a.href = BASE + '/event_templates/instantiate/' + t.id;
            $a.setAttribute('data-search', t.search);

            var $name = document.createElement('div');
            var $nameLabel = document.createElement('span');
            $nameLabel.className = 'et-tp-item-name';
            $nameLabel.textContent = t.name;
            $name.appendChild($nameLabel);
            if (t.orgName) {
                var $meta = document.createElement('span');
                $meta.className = 'et-tp-item-meta';
                $meta.textContent = t.orgName;
                $name.appendChild($meta);
            }
            if (t.modified) {
                var $mod = document.createElement('span');
                $mod.className = 'et-tp-item-meta';
                $mod.textContent = 'modified ' + t.modified;
                $name.appendChild($mod);
            }
            $a.appendChild($name);
            if (t.description) {
                var $d = document.createElement('div');
                $d.className = 'et-tp-item-desc';
                $d.textContent = t.description;
                $a.appendChild($d);
            }
            $list.appendChild($a);
        });
    }

    function filter(term) {
        term = (term || '').toLowerCase().trim();
        var $items = document.querySelectorAll('#et-template-picker-list .et-tp-item');
        $items.forEach(function ($it) {
            if (!term) { $it.style.display = ''; return; }
            var hay = $it.getAttribute('data-search') || '';
            $it.style.display = hay.indexOf(term) === -1 ? 'none' : '';
        });
    }

    window.openEventTemplatePicker = function () {
        var $modal = document.getElementById('et-template-picker-modal');
        var $loading = document.getElementById('et-template-picker-loading');
        var $search = document.getElementById('et-template-picker-search');
        if ($search) { $search.value = ''; }
        if ($loading) { $loading.style.display = ''; }
        render([]);
        // Prefer Bootstrap 5's native API when the bundle is present
        // (that's the case on every Overmind BS5 page). Fall back to
        // jQuery's $.modal('show') so this element still works if it
        // ever lands on a BS2 page under the Overmind theme.
        if (window.bootstrap && window.bootstrap.Modal && $modal) {
            window.bootstrap.Modal.getOrCreateInstance($modal).show();
            if ($search) { setTimeout(function () { $search.focus(); }, 150); }
        } else if (window.jQuery && $modal) {
            window.jQuery($modal).modal('show');
            if ($search) { setTimeout(function () { $search.focus(); }, 150); }
        }
        load().then(function (items) {
            if ($loading) { $loading.style.display = 'none'; }
            render(items);
        }).catch(function (err) {
            if ($loading) {
                $loading.style.color = '#c33';
                $loading.textContent = 'Failed to load templates: ' +
                    (err && err.message ? err.message : err);
            }
        });
    };

    document.addEventListener('DOMContentLoaded', function () {
        var $search = document.getElementById('et-template-picker-search');
        if ($search) {
            $search.addEventListener('input', function () { filter($search.value); });
        }
    });
})();
</script>
