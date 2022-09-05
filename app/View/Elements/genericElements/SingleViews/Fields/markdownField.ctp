<?php
$random = 'r-' . mt_rand();
$markdown = Hash::get($data, $field['path']);
echo $this->element('genericElements/assetLoader', [
    'js' => [
        'markdown-it',
        'mermaid',
    ],
]);
$invalidMarkdown = substr_count($markdown, PHP_EOL) <= 2;
?>

<div class="markdown <?= $random ?>">
    <?php if ($invalidMarkdown) : ?>
        <pre id="raw"><?= h($markdown) ?></pre>
    <?php endif; ?>
</div>

<?php if (!$invalidMarkdown) : ?>
    <script>
        $(function() {
            var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
            md = window.markdownit('default');
            md.disable(['link', 'image'])
            md.renderer.rules.table_open = function() {
                return '<table class="table table-striped">\n';
            };
            const fenceBackup = md.renderer.rules.fence.bind(md.renderer.rules)
            // https://github.com/tylingsoft/markdown-it-mermaid/blob/master/src/index.js
            md.renderer.rules.fence = function(tokens, idx, options, env, slf) {
                const token = tokens[idx]
                const code = token.content.trim()
                if (token.info === 'mermaid') {
                    return renderMermaid(code)
                }
                const firstLine = code.split(/\n/)[0].trim()
                if (firstLine === 'gantt' || firstLine === 'sequenceDiagram' || firstLine.match(/^graph (?:TB|BT|RL|LR|TD);?$/)) {
                    return renderMermaid(code)
                }
                return fenceBackup(tokens, idx, options, env, slf)
            }
            var mermaidTheme = 'neutral'
            mermaid.mermaidAPI.initialize({
                startOnLoad: false,
                theme: mermaidTheme,
            })
            var $md = $('.markdown.<?= $random ?>')
            $md.html(md.render(originalRaw))
        })

        function renderMermaid(code) {
            try {
                var res = mermaid.parse(code)
                var result = mermaid.mermaidAPI.render('mermaid-graph', code)
                return '<div class="mermaid">' + (result !== undefined ? result : '- error while parsing mermaid graph -') + '</div>'
            } catch (err) {
                return '<pre>' + 'mermaid error:\n' + (err.message ? err.message : err.str) + '</pre>'
            }
        }
    </script>
<?php endif; ?>
