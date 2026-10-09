<?php
/*
 * Read-only drawing of the workflow a trigger starts. The core element does
 * the same with jQuery and doT, neither of which a BS5 page loads.
 */
$graph = $data['Workflow']['data'] ?? [];
// The editor stores its frame annotations next to the nodes.
unset($graph['_frames']);

echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['drawflow.min'],
]);
?>

<div class="card shadow-sm mb-3">
    <div class="card-header bg-transparent d-flex align-items-center justify-content-between py-3">
        <div class="d-flex align-items-center gap-2">
            <i class="fas fa-diagram-project text-secondary"></i>
            <span class="fw-semibold"><?= h($data['Workflow']['name']) ?></span>
            <span class="text-muted small">
                <?= h(__n('%s node', '%s nodes', count($graph), count($graph))) ?>
            </span>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-sm btn-light" data-wf-graph-fit title="<?= h(__('Fit to view')) ?>">
                <i class="fas fa-expand"></i>
            </button>
            <a class="btn btn-sm btn-primary" href="<?= h($baseurl . '/workflows/editor/' . (int)$data['Workflow']['id']) ?>">
                <i class="fas fa-code me-1"></i><?= __('Open in editor') ?>
            </a>
        </div>
    </div>
    <?php if (empty($graph)): ?>
        <div class="card-body text-muted small"><?= __('This workflow has no node yet.') ?></div>
    <?php else: ?>
        <div class="ov-wf-graph" data-wf-graph></div>
        <script type="application/json" data-wf-graph-data><?= json_encode($graph, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
    <?php endif; ?>
</div>

<?php
echo $this->element('genericElementsBS5/Cards/card_collapsible', [
    'title' => __('Graph data'),
    'icon' => 'code',
    'collapsed' => true,
    'content' => $this->element('genericElementsBS5/Badges/json', ['json' => $graph, 'full' => true]),
]);
?>

<script>
(function () {
    function esc(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    function blockHtml(block) {
        var icon = '';
        if (block.icon) {
            icon = '<i class="fa-fw ' + esc(block.icon_class || 'fas') + ' fa-' + esc(block.icon) + '"></i>';
        } else if (block.icon_path) {
            icon = '<img src="<?= h($baseurl) ?>/img/' + esc(block.icon_path) + '" alt="" width="18" height="18">';
        }
        return '<div class="ov-wf-node">' + icon
            + '<strong>' + esc(block.name) + '</strong>'
            + (block.is_misp_module ? '<sup class="text-muted">misp-module</sup>' : '')
            + '</div>';
    }

    function fit(editor) {
        var nodes = Object.values(editor.drawflow.drawflow.Home.data);
        if (!nodes.length) return;
        var box = editor.container.getBoundingClientRect();
        var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nodes.forEach(function (node) {
            minX = Math.min(minX, node.pos_x);
            minY = Math.min(minY, node.pos_y);
            maxX = Math.max(maxX, node.pos_x + 200);
            maxY = Math.max(maxY, node.pos_y + 60);
        });
        var zoom = Math.min(1, (box.width - 40) / (maxX - minX), (box.height - 40) / (maxY - minY));
        zoom = Math.max(editor.zoom_min, zoom);
        // The precanvas scales around its own centre, which is the container's.
        editor.zoom = zoom;
        editor.zoom_last_value = zoom;
        editor.canvas_x = (box.width / 2 - (minX + maxX) / 2) * zoom;
        editor.canvas_y = (box.height / 2 - (minY + maxY) / 2) * zoom;
        editor.precanvas.style.transform = 'translate(' + editor.canvas_x + 'px, '
            + editor.canvas_y + 'px) scale(' + zoom + ')';
    }

    function draw(root) {
        var container = root.querySelector('[data-wf-graph]');
        var source = root.querySelector('[data-wf-graph-data]');
        if (!container || !source || container.dataset.drawn) return;
        if (!container.offsetWidth) return;
        container.dataset.drawn = '1';

        var graph = JSON.parse(source.textContent);
        var editor = new Drawflow(container);
        editor.editor_mode = 'view';
        editor.draggable_inputs = false;
        editor.zoom_min = 0.3;
        editor.start();

        Object.values(graph).forEach(function (block) {
            // Keep the saved ids so the connections below resolve.
            editor.nodeId = block.id;
            editor.addNode(
                block.name,
                Object.keys(block.inputs || {}).length,
                Object.keys(block.outputs || {}).length,
                block.pos_x,
                block.pos_y,
                block.class,
                block.data,
                blockHtml(block.data || {})
            );
        });
        Object.values(graph).forEach(function (block) {
            Object.keys(block.inputs || {}).forEach(function (inputName) {
                (block.inputs[inputName].connections || []).forEach(function (connection) {
                    editor.addConnection(connection.node, block.id, connection.input, inputName);
                });
            });
        });
        fit(editor);

        var fitButton = document.querySelector('[data-wf-graph-fit]');
        if (fitButton) {
            fitButton.addEventListener('click', function () { fit(editor); });
        }
    }

    function init() {
        var pane = document.getElementById('tab-execution-path');
        if (!pane) return;
        // A Drawflow canvas measured inside a hidden pane has no size to fit to.
        draw(pane);
        var tab = document.querySelector('a[href="#tab-execution-path"]');
        if (tab) {
            tab.addEventListener('shown.bs.tab', function () { draw(pane); });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
</script>
