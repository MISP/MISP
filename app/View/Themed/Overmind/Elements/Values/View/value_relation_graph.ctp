<?php
/**
 * The Relationships tab's Neighbourhood card: a static peek at the value's
 * neighbourhood, and the full graph it opens.
 *
 * Both draw from one `/values/graph` read: the peek from it directly, the
 * full graph — the Pivot Explorer seeded on the value — from the same
 * payload when it is opened. Behaviour lives in value-neighbourhood.js and
 * value-neighbourhood-peek.js.
 *
 * Lazily loaded from ValuesController::viewRelationGraph.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 * @var array $pivotLabels `plan`, `permitted`
 */
$value = $valueIntelligence['value'];
$cardId = 'vn-' . substr(md5($value), 0, 8);

echo $this->element('genericElements/assetLoader', array(
    'js' => array('pivotick.iife', 'misp-pivot-nodes', 'pivot-sidebar-model',
        'pivot-sidebar-view', 'pivot-explorer', 'value-neighbourhood',
        'value-neighbourhood-peek'),
    'css' => array('pivotick', 'pivot-explorer', 'pivot-sidebar',
        'value-neighbourhood'),
));

$config = array(
    'value' => $value,
    'b64' => $valueB64,
    'baseurl' => $baseurl,
    'labelPlan' => $pivotLabels['plan'],
    'permitted' => $pivotLabels['permitted'],
    'orgUuid' => isset($me['Organisation']['uuid']) ? $me['Organisation']['uuid'] : '',
    'siteAdmin' => !empty($me['Role']['perm_site_admin']),
    'valueCard' => (bool)Configure::read('MISP.value_hover_card'),
    'canEnrich' => $this->Acl->canAccess('values', 'enrichmentRun'),
    'text' => array(
        'libMissing' => __('Graph library failed to load.'),
        'loadFailed' => __('Failed to load the neighbourhood.'),
    ),
);
?>
<div class="card shadow-sm mb-3 vp-panel" id="<?= h($cardId) ?>" data-vn-card
     style="--vp-panel-color: var(--bs-secondary-color);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Neighbourhood'),
        'panelIcon' => 'fas fa-circle-nodes',
        'panelColor' => 'var(--bs-secondary-color)',
        'panelSub' => h(__('What it leads to, and where it sits')),
    )) ?>

    <div data-vn-peek>
        <div class="text-center py-4 text-muted small" data-vn-loading>
            <div class="misp-loader misp-loader-sm mb-2" role="status"></div>
            <?= h(__('Reading the neighbourhood…')) ?>
        </div>
    </div>

    <?php
    /*
     * The config is a literal in the script rather than a JSON block beside
     * it: the fragment loader re-creates every script it brings without its
     * `type`, so a JSON block would run as JavaScript.
     */
    ?>
    <script>
    (function () {
        var config = <?= json_encode($config) ?>;
        var card = document.getElementById(<?= json_encode($cardId) ?>);
        if (!card) return;
        var peekEl = card.querySelector('[data-vn-peek]');

        function theme() {
            return document.documentElement.getAttribute('data-misp-mode') === 'dark' ? 'dark' : 'light';
        }

        function ready() {
            return typeof window.Pivotick === 'function' && window.MispPivotNodes
                && window.MispPivotSidebar && window.MispPivotSidebarView
                && window.MispPivotExplorer && window.MispValueNeighbourhood
                && window.MispValueNeighbourhoodPeek;
        }

        function fail(message) {
            peekEl.innerHTML = '';
            var p = document.createElement('p');
            p.className = 'text-danger small m-3';
            p.textContent = message;
            peekEl.appendChild(p);
        }

        var overlay = null;
        function openFull(seed) {
            if (overlay) {
                overlay.classList.remove('d-none');
                return;
            }
            overlay = document.createElement('div');
            overlay.className = 'vn-overlay';
            overlay.innerHTML = '<div class="vn-overlay-bar"><span class="vn-overlay-title"></span>'
                + '<button type="button" class="btn btn-sm btn-outline-secondary" data-vn-close></button></div>'
                + '<div class="vn-overlay-stage"></div>';
            var title = overlay.querySelector('.vn-overlay-title');
            title.appendChild(document.createTextNode(<?= json_encode(__('Neighbourhood of')) ?> + ' '));
            var mono = document.createElement('span');
            mono.className = 'vn-mono';
            mono.textContent = config.value;
            title.appendChild(mono);
            var close = overlay.querySelector('[data-vn-close]');
            close.textContent = <?= json_encode(__('Close')) ?>;
            close.addEventListener('click', function () { overlay.classList.add('d-none'); });
            document.body.appendChild(overlay);
            var stage = overlay.querySelector('.vn-overlay-stage');
            window.MispValueNeighbourhood.explorer(Object.assign({}, config, {
                containerEl: stage, loaderEl: null, seed: seed
            })).init();
        }

        var tries = 0;
        (function start() {
            if (!ready()) {
                // The loader fetches the scripts after running this one.
                if (++tries > 200) return fail(config.text.libMissing);
                window.setTimeout(start, 50);
                return;
            }
            var V = window.MispValueNeighbourhood;
            V.fetchSeed(config.baseurl, config.b64).then(function (seed) {
                peekEl.innerHTML = '';
                var shell = window.MispPivotExplorer.create(V.host(Object.assign({}, config, { containerEl: null })));
                return window.MispValueNeighbourhoodPeek(peekEl, seed, {
                    kit: shell.kit,
                    theme: theme(),
                    onOpen: function () { openFull(seed); }
                });
            }).catch(function (err) {
                console.error('[value-neighbourhood]', err);
                fail(config.text.loadFailed);
            });
        })();
    })();
    </script>
</div>
