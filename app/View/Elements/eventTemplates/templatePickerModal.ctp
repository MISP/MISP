<?php
/*
 * Searchable modal for "Add Event → From Template" (PRD §5.2 F2.2).
 * Rendered once on any page that needs the affordance (currently the
 * Events index). Exposes window.openEventTemplatePicker() as the
 * global entry point — matches the toolbar onClick convention
 * (ListTopBar/scaffold calls the name it finds on window).
 *
 * On first open, AJAX-fetches /event_templates/index.json and renders
 * the list; subsequent opens reuse the cache for the rest of the page
 * lifetime. The user picks a row → browser navigates to
 * /event_templates/instantiate/{id} which renders the user form.
 */
?>
<div id="et-template-picker-modal" class="modal hide fade" tabindex="-1" role="dialog"
     aria-labelledby="et-template-picker-title" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h3 id="et-template-picker-title"><?php echo __('Create event from template'); ?></h3>
    </div>
    <div class="modal-body">
        <input type="text" id="et-template-picker-search" class="input-block-level"
               placeholder="<?php echo __('Filter by name, description, or organisation…'); ?>">
        <div id="et-template-picker-loading" style="color:#888; padding:10px;">
            <?php echo __('Loading templates…'); ?>
        </div>
        <div id="et-template-picker-list"
             style="max-height:440px; overflow-y:auto; border:1px solid #eee; border-radius:3px;">
        </div>
        <div id="et-template-picker-empty" style="display:none; padding:14px; color:#888;">
            <em><?php echo __('No active event templates are visible to you on this instance.'); ?></em>
            <a href="<?php echo h($baseurl . '/event_templates/index'); ?>" style="margin-left:8px;">
                <?php echo __('Review templates'); ?></a>
            <span style="margin-left:4px;"><?php echo __('(you may need to enable one first)'); ?></span>
            <?php if ($this->Acl->canAccess('eventTemplates', 'add')): ?>
                <a href="<?php echo h($baseurl . '/event_templates/add'); ?>"
                   style="margin-left:8px;">
                    <?php echo __('Build one'); ?></a>
            <?php endif; ?>
        </div>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn" data-dismiss="modal">
            <?php echo __('Cancel'); ?>
        </button>
    </div>
</div>

<style>
#et-template-picker-modal { width: 640px; }
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
    var BASE = <?php echo json_encode($baseurl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

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
                // most-recently-modified first
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
        if (window.jQuery && $modal) {
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
