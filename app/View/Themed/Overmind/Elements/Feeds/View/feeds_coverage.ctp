<?php
/*
 * Feed coverage tool. Answers "how much of this feed's cached data do I already
 * get from somewhere else?" by intersecting this feed's Redis cache with the
 * caches of the sources kept on the Include side.
 *
 * $other_feeds (viewVar) => ['Feed' => [...], 'Server' => [...]], each entry
 * carrying id / name / url / matching_values. getAllCachingEnabledFeeds() was
 * called with $intersectingOnly, so only sources that actually overlap are here.
 *
 * The legacy tool was jQuery-based; BS5 pages load no jQuery, so the picker and
 * the coverage request are reimplemented inline below.
 */
$feed = $data['Feed'] ?? [];
$feedId = (int)($feed['id'] ?? 0);
$cachedElements = (int)($feed['cached_elements'] ?? 0);
$coverage = $feed['coverage_by_other_feeds'] ?? '0%';

$sources = ['Feed' => __('Feeds'), 'Server' => __('Servers')];

// Most-overlapping first — that is the interesting end of the list.
$entries = [];
foreach (array_keys($sources) as $scope) {
    $scopeEntries = $other_feeds[$scope] ?? [];
    usort($scopeEntries, function ($a, $b) {
        return ($b['matching_values'] ?? 0) <=> ($a['matching_values'] ?? 0);
    });
    $entries[$scope] = $scopeEntries;
}
$hasAnySource = !empty($entries['Feed']) || !empty($entries['Server']);
$uid = 'cov' . dechex(mt_rand());
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <div class="fw-bold mb-1 d-flex align-items-center gap-2">
            <i class="fas fa-chart-pie text-muted"></i>
            <?= __('Feed coverage tool') ?>
        </div>
        <p class="text-muted small">
            <?= __('Share of this feed\'s cached values that are also present in the selected sources.') ?>
        </p>

        <!-- CURRENT COVERAGE -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Coverage by the selected sources') ?>
            </div>
            <div class="progress" style="height:1.5rem;">
                <div id="<?= $uid ?>-bar" class="progress-bar" role="progressbar"
                     style="width: <?= h($coverage) ?>;"
                     aria-valuenow="<?= h(rtrim($coverage, '%')) ?>"
                     aria-valuemin="0" aria-valuemax="100">
                    <?= h($coverage) ?>
                </div>
            </div>
            <div class="text-muted mt-1" style="font-size:0.75rem;">
                <?= __('Out of %s cached values in this feed.', number_format($cachedElements)) ?>
            </div>
        </div>

        <?php if (!$hasAnySource): ?>
            <div class="alert alert-info d-flex mb-0" role="alert">
                <i class="fas fa-circle-info me-2 mt-1"></i>
                <div><?= __('No other caching-enabled feed or server overlaps with this one, so there is nothing to compare against.') ?></div>
            </div>
        <?php else: ?>

            <?php foreach ($sources as $scope => $scopeLabel): ?>
                <?php if (empty($entries[$scope])) { continue; } ?>
                <div class="mb-4">
                    <div class="fw-semibold mb-2"><?= h($scopeLabel) ?></div>
                    <div class="row g-2 align-items-center">

                        <div class="col-md-5">
                            <label class="text-muted small text-uppercase fw-bold mb-1"
                                   for="<?= $uid ?>-<?= h($scope) ?>-include"><?= __('Include') ?></label>
                            <select id="<?= $uid ?>-<?= h($scope) ?>-include"
                                    class="form-select" size="6" multiple>
                                <?php foreach ($entries[$scope] as $entry): ?>
                                    <option value="<?= h($entry['id']) ?>">
                                        [<?= $cachedElements > 0
                                            ? round(100 * ($entry['matching_values'] ?? 0) / $cachedElements)
                                            : 0 ?>%]
                                        <?= h($entry['name']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="col-md-2 d-flex flex-md-column justify-content-center gap-2 py-2">
                            <button type="button" class="btn btn-outline-secondary btn-sm"
                                    data-cov-move="left" data-cov-scope="<?= h($scope) ?>"
                                    title="<?= __('Include selected') ?>">
                                <i class="fas fa-arrow-left"></i>
                            </button>
                            <button type="button" class="btn btn-outline-secondary btn-sm"
                                    data-cov-move="right" data-cov-scope="<?= h($scope) ?>"
                                    title="<?= __('Exclude selected') ?>">
                                <i class="fas fa-arrow-right"></i>
                            </button>
                        </div>

                        <div class="col-md-5">
                            <label class="text-muted small text-uppercase fw-bold mb-1"
                                   for="<?= $uid ?>-<?= h($scope) ?>-exclude"><?= __('Exclude') ?></label>
                            <select id="<?= $uid ?>-<?= h($scope) ?>-exclude"
                                    class="form-select" size="6" multiple></select>
                        </div>

                    </div>
                </div>
            <?php endforeach; ?>

            <div class="d-flex align-items-center gap-2">
                <button type="button" id="<?= $uid ?>-submit" class="btn btn-primary">
                    <i class="fas fa-calculator me-1"></i><?= __('Check coverage') ?>
                </button>
                <span id="<?= $uid ?>-status" class="text-muted small"></span>
            </div>

        <?php endif; ?>

    </div>
</div>

<?php if ($hasAnySource): ?>
<script>
(function () {
    var uid = <?= json_encode($uid) ?>;
    var feedId = <?= json_encode($feedId) ?>;
    var scopes = <?= json_encode(array_keys(array_filter($entries))) ?>;
    var base = (typeof baseurl !== 'undefined' ? baseurl : '');

    function box(scope, side) {
        return document.getElementById(uid + '-' + scope + '-' + side);
    }

    // Move the selected options between the Include and Exclude lists.
    document.querySelectorAll('[data-cov-move]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var scope = btn.dataset.covScope;
            var from = box(scope, btn.dataset.covMove === 'right' ? 'include' : 'exclude');
            var to = box(scope, btn.dataset.covMove === 'right' ? 'exclude' : 'include');
            if (!from || !to) return;
            Array.prototype.slice.call(from.selectedOptions).forEach(function (opt) {
                opt.selected = false;
                to.appendChild(opt);
            });
        });
    });

    var submit = document.getElementById(uid + '-submit');
    var status = document.getElementById(uid + '-status');
    var bar = document.getElementById(uid + '-bar');

    submit.addEventListener('click', function () {
        var body = new URLSearchParams();
        scopes.forEach(function (scope) {
            var include = box(scope, 'include');
            if (!include) return;
            Array.prototype.slice.call(include.options).forEach(function (opt) {
                body.append(scope + '[]', opt.value);
            });
        });

        submit.disabled = true;
        status.textContent = <?= json_encode(__('Computing…')) ?>;

        // Accept: application/json makes AppController treat this as REST, which
        // unlocks the action for the SecurityComponent; the CSRF header is still
        // sent so the request is rejected if the session is gone.
        fetch(base + '/feeds/feedCoverage/' + feedId, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': typeof getCsrfToken === 'function' ? getCsrfToken() : ''
            },
            body: body.toString()
        })
            .then(function (r) { return r.text(); })
            .then(function (text) {
                var value = parseFloat(String(text).replace(/^"|"$/g, ''));
                if (isNaN(value)) {
                    status.textContent = <?= json_encode(__('Unexpected response.')) ?>;
                    return;
                }
                bar.style.width = value + '%';
                bar.textContent = value + '%';
                bar.setAttribute('aria-valuenow', value);
                status.textContent = '';
            })
            .catch(function () {
                status.textContent = <?= json_encode(__('Could not compute the coverage.')) ?>;
            })
            .finally(function () { submit.disabled = false; });
    });
}());
</script>
<?php endif; ?>
