<?php
/**
 * Statistics tags tab: event tags by enabled taxonomy, the rest as custom
 * tags, from the tags REST statistics, drawn client-side.
 */
$uid = 'stats-tags-' . mt_rand();
?>
<div class="row g-3 mb-3" id="<?= h($uid) ?>">
    <div class="col-lg-5">
        <div class="card shadow-sm h-100">
            <div class="card-header fw-semibold"><?= __('Events per taxonomy') ?></div>
            <div class="card-body">
                <div data-tags-loading><?= $this->element('genericElementsBS5/loader') ?></div>
                <div class="mx-auto" style="max-width: 280px;"><canvas data-tags-chart hidden></canvas></div>
                <ul class="list-unstyled small mt-3 mb-0" data-tags-legend></ul>
            </div>
        </div>
    </div>
    <div class="col-lg-7">
        <div class="card shadow-sm h-100">
            <div class="card-header d-flex align-items-center gap-2">
                <span class="fw-semibold"><?= __('Tags') ?></span>
                <span class="badge text-bg-secondary d-none" data-tags-filter-label></span>
                <input type="search" class="form-control form-control-sm ms-auto" style="max-width: 220px;"
                       placeholder="<?= h(__('Filter tags')) ?>" aria-label="<?= h(__('Filter tags')) ?>" data-tags-search>
            </div>
            <div class="table-responsive" style="max-height: 32rem;">
                <table class="table table-sm table-hover align-middle mb-0">
                    <thead class="sticky-top">
                        <tr>
                            <th><?= __('Tag') ?></th>
                            <th><?= __('Taxonomy') ?></th>
                            <th class="text-end"><?= __('Events') ?></th>
                        </tr>
                    </thead>
                    <tbody data-tags-rows></tbody>
                </table>
            </div>
            <div class="card-footer small text-body-secondary" data-tags-footer></div>
        </div>
    </div>
</div>
<script>
(function () {
    var root = document.getElementById(<?= json_encode($uid) ?>);
    var text = <?= json_encode([
        'failed' => __('Could not load the tag statistics.'),
        'none' => __('No event carries a tag.'),
        'custom' => __('Custom tags'),
        'other' => __('Other'),
        'shown' => __('%s of %s tags'),
        'events' => __('%s events'),
    ]) ?>;
    var PALETTE = [
        '#3B82F6','#10B981','#F59E0B','#EF4444','#8B5CF6',
        '#EC4899','#14B8A6','#F97316','#6366F1','#84CC16',
        '#06B6D4'
    ];
    var OTHER_COLOUR = '#94A3B8';
    var ROW_LIMIT = 200;
    var tags = [];
    var groupFilter = null;

    fetch(<?= json_encode($baseurl . '/users/statistics/tags.json') ?>, {
        credentials: 'same-origin',
        headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
    }).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    }).then(draw).catch(function () {
        root.querySelector('[data-tags-loading]').textContent = text.failed;
    });

    function draw(data) {
        var seen = {};
        Object.keys(data.flatData || {}).forEach(function (taxonomy) {
            var entries = data.flatData[taxonomy];
            Object.keys(entries).forEach(function (key) {
                var name = entries[key].name;
                if (seen[name]) return;
                seen[name] = true;
                tags.push({name: name, events: +entries[key].size || 0, group: taxonomy === 'custom' ? text.custom : taxonomy});
            });
        });
        tags.sort(function (a, b) { return b.events - a.events || a.name.localeCompare(b.name); });
        root.querySelector('[data-tags-loading]').remove();
        if (!tags.length) {
            root.querySelector('[data-tags-legend]').textContent = text.none;
            renderRows();
            return;
        }

        var totals = {};
        tags.forEach(function (tag) { totals[tag.group] = (totals[tag.group] || 0) + tag.events; });
        var groups = Object.keys(totals).sort(function (a, b) { return totals[b] - totals[a]; });
        var slices = groups.slice(0, PALETTE.length).map(function (group, i) {
            return {label: group, value: totals[group], colour: PALETTE[i], groups: [group]};
        });
        if (groups.length > PALETTE.length) {
            var rest = groups.slice(PALETTE.length);
            slices.push({
                label: text.other,
                value: rest.reduce(function (sum, group) { return sum + totals[group]; }, 0),
                colour: OTHER_COLOUR,
                groups: rest
            });
        }
        var sum = slices.reduce(function (s, slice) { return s + slice.value; }, 0);

        var canvas = root.querySelector('[data-tags-chart]');
        canvas.hidden = false;
        new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: slices.map(function (s) { return s.label; }),
                datasets: [{
                    data: slices.map(function (s) { return s.value; }),
                    backgroundColor: slices.map(function (s) { return s.colour; }),
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                cutout: '68%',
                responsive: true,
                plugins: {
                    legend: {display: false},
                    tooltip: {callbacks: {label: function (ctx) {
                        return ' ' + ctx.raw.toLocaleString() + ' (' + Math.round(ctx.raw / sum * 100) + '%)';
                    }}}
                },
                onClick: function (event, elements) {
                    if (elements.length) pick(slices[elements[0].index]);
                }
            }
        });

        var legend = root.querySelector('[data-tags-legend]');
        slices.forEach(function (slice) {
            var item = document.createElement('li');
            item.className = 'd-flex align-items-center gap-2 py-1';
            item.style.cursor = 'pointer';
            var swatch = document.createElement('span');
            swatch.style.cssText = 'width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + slice.colour;
            var label = document.createElement('span');
            label.className = 'text-truncate';
            label.textContent = slice.label;
            var share = document.createElement('span');
            share.className = 'ms-auto text-body-secondary';
            share.textContent = Math.round(slice.value / sum * 100) + '%';
            item.append(swatch, label, share);
            item.addEventListener('click', function () { pick(slice); });
            legend.appendChild(item);
        });

        function pick(slice) {
            groupFilter = groupFilter === slice ? null : slice;
            var badge = root.querySelector('[data-tags-filter-label]');
            badge.textContent = groupFilter ? groupFilter.label : '';
            badge.classList.toggle('d-none', !groupFilter);
            legend.querySelectorAll('li').forEach(function (li, i) {
                li.classList.toggle('opacity-50', groupFilter !== null && slices[i] !== groupFilter);
            });
            renderRows();
        }

        root.querySelector('[data-tags-search]').addEventListener('input', renderRows);
        renderRows();
    }

    function renderRows() {
        var needle = root.querySelector('[data-tags-search]').value.trim().toLowerCase();
        var shown = tags.filter(function (tag) {
            return (!groupFilter || groupFilter.groups.indexOf(tag.group) !== -1)
                && (!needle || tag.name.toLowerCase().indexOf(needle) !== -1);
        });
        var body = root.querySelector('[data-tags-rows]');
        body.replaceChildren.apply(body, shown.slice(0, ROW_LIMIT).map(function (tag) {
            var tr = document.createElement('tr');
            [tag.name, tag.group, tag.events.toLocaleString()].forEach(function (value, i) {
                var td = document.createElement('td');
                td.textContent = value;
                if (i === 1) td.className = 'text-body-secondary';
                if (i === 2) td.className = 'text-end fw-semibold';
                tr.appendChild(td);
            });
            return tr;
        }));
        root.querySelector('[data-tags-footer]').textContent = text.shown
            .replace('%s', Math.min(shown.length, ROW_LIMIT).toLocaleString())
            .replace('%s', shown.length.toLocaleString());
    }
})();
</script>
