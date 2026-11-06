<?php
/**
 * The AI module's installation guide (ServersController::aiConnectorGuide),
 * opened with openModal() from the status card of the AI settings tab.
 *
 * The guide is docs/INSTALL.md of the module's repository, split by
 * Module::splitAiGuide(): the overview above the tabs, one tab per `## `
 * section. markdown-it renders it here, and mermaid its diagrams, both loaded
 * on first use. What the file writes for GitHub becomes the modal's own
 * layout: an alert (`> [!NOTE]`) a callout, a `#section` link a tab switch, a
 * relative link a link to the file's neighbour on GitHub.
 *
 * View variables: intro, sections, or error when the download failed;
 * guidePage (the file on GitHub); openTab (section key to open on, or null).
 */

$assetUrl = function ($name) use ($queryVersion) {
    $url = $this->Html->assetUrl($name, ['pathPrefix' => Configure::read('App.jsBaseUrl'), 'ext' => '.js']);
    $version = Configure::read('Asset.timestamp') === 'cached' && file_exists(WWW_ROOT . $url)
        ? filemtime(WWW_ROOT . $url)
        : null;
    return $url . '?v=' . ($version ?: $queryVersion);
};

$sections = $sections ?? [];
// Same detection as the event-template dependency page.
$isDocker = file_exists('/.dockerenv');
if (!$isDocker && is_readable('/proc/1/cgroup')) {
    $isDocker = strpos((string)@file_get_contents('/proc/1/cgroup'), 'docker') !== false;
}
$install = $isDocker ? 'docker' : 'standard-install';
if (isset($sections[$install])) {
    $sections = [$install => $sections[$install]] + $sections;
}
$active = isset($sections[$openTab]) ? $openTab : key($sections);

$icons = [
    'docker' => 'fab fa-docker',
    'standard-install' => 'fas fa-server',
    'llm-endpoint' => 'fas fa-microchip',
    'troubleshooting' => 'fas fa-stethoscope',
];
$uid = 'aicGuide' . dechex(mt_rand());
$githubLink = sprintf(
    '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
    h($guidePage),
    h('MISP/ai-connector · docs/INSTALL.md')
);
?>
<div id="<?= h($uid) ?>"
     data-markdown-url="<?= h($assetUrl('markdown-it')) ?>"
     data-mermaid-url="<?= h($assetUrl('mermaid')) ?>"
     data-link-base="<?= h($guidePage) ?>"
     style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: clip;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'info',
        'eyebrow' => __('AI module'),
        'title' => __('Install ai_connector'),
        'titleIcon' => 'fas fa-book-open',
        'description' => __('Install the module, connect it to this MISP and to a language model, step by step.'),
        'close' => true,
    ]) ?>

    <?php if (isset($error)): ?>
        <div class="px-4 py-3">
            <div class="alert alert-warning d-flex align-items-start gap-3 mb-0" role="alert">
                <i class="fas fa-cloud-arrow-down mt-1"></i>
                <div>
                    <div class="fw-semibold"><?= __('The guide could not be downloaded') ?></div>
                    <div class="small"><?= __('MISP fetches it from the module\'s repository on GitHub, and the download failed. Read it there instead.') ?></div>
                    <a class="btn btn-sm btn-primary mt-2" href="<?= h($guidePage) ?>" target="_blank" rel="noopener noreferrer">
                        <i class="fab fa-github me-1"></i><?= __('Open the guide on GitHub') ?>
                    </a>
                    <div class="small text-muted font-monospace mt-2"><?= h($error) ?></div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <div class="px-4 pt-3">
            <div class="markdown-preview-body aic-md aic-intro" data-aic-md hidden><?= h($intro) ?></div>
        </div>

        <?php // One parent for the tabs and the panes, so the tab bar stays in view while a pane scrolls. ?>
        <div>
            <div class="px-4 pt-3 aic-guide-tabs">
                <ul class="nav nav-tabs" role="tablist">
                    <?php foreach ($sections as $key => $section): ?>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link<?= $key === $active ? ' active' : '' ?>" type="button" role="tab"
                                    data-bs-toggle="tab" data-bs-target="#<?= h($uid . '-' . $key) ?>">
                                <i class="<?= h($icons[$key] ?? 'fas fa-file-lines') ?> me-1"></i><?= h($section['title']) ?>
                                <?php if ($isDocker && $key === 'docker'): ?>
                                    <span class="badge rounded-pill bg-primary ms-1"><?= __('Detected') ?></span>
                                <?php endif; ?>
                            </button>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <div class="tab-content px-4 py-3">
                <?php foreach ($sections as $key => $section): ?>
                    <div class="tab-pane fade<?= $key === $active ? ' show active' : '' ?>"
                         id="<?= h($uid . '-' . $key) ?>" role="tabpanel">
                        <div class="markdown-preview-body aic-md" data-aic-md hidden><?= h($section['markdown']) ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'bleed' => true,
        'metaHtml' => __('From %s, refreshed daily', $githubLink),
        'cancel' => ['label' => __('Close'), 'icon' => ''],
        'submit' => false,
    ]) ?>
</div>
<?php if (!isset($error)): ?>
<script>
(function () {
    const root = document.getElementById(<?= json_encode($uid) ?>);
    const L = <?= json_encode([
        'copy' => __('Copy'),
        'copied' => __('Command copied'),
        'note' => __('Note'),
        'tip' => __('Tip'),
        'important' => __('Important'),
        'warning' => __('Warning'),
        'caution' => __('Caution'),
    ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const alertIcons = {
        note: 'circle-info', tip: 'lightbulb', important: 'circle-exclamation',
        warning: 'triangle-exclamation', caution: 'hand'
    };

    function script(url, name) {
        if (window[name]) return Promise.resolve(window[name]);
        return new Promise(function (resolve, reject) {
            const tag = document.createElement('script');
            tag.src = url;
            tag.onload = function () { window[name] ? resolve(window[name]) : reject(); };
            tag.onerror = reject;
            document.head.appendChild(tag);
        });
    }

    function tabFor(anchor) {
        return root.querySelector('[data-bs-target="#' + root.id + '-' + CSS.escape(anchor) + '"]');
    }

    function links(el) {
        el.querySelectorAll('a[href]').forEach(function (a) {
            const href = a.getAttribute('href');
            if (href.startsWith('#')) {
                const tab = tabFor(href.slice(1));
                if (!tab) return;
                a.addEventListener('click', function (event) {
                    event.preventDefault();
                    bootstrap.Tab.getOrCreateInstance(tab).show();
                    tab.scrollIntoView({block: 'nearest', behavior: 'smooth'});
                });
                return;
            }
            // Relative links point at the guide's neighbours in its repository.
            a.href = new URL(href, root.dataset.linkBase).href;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
        });
    }

    // GitHub's `> [!NOTE]` alerts: markdown-it leaves them as blockquotes.
    function alerts(el) {
        el.querySelectorAll('blockquote').forEach(function (quote) {
            const first = quote.firstElementChild;
            const match = first && first.tagName === 'P' && first.innerHTML.match(/^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*/);
            if (!match) return;
            const type = match[1].toLowerCase();
            first.innerHTML = first.innerHTML.slice(match[0].length);
            if (!first.textContent.trim()) first.remove();
            const box = document.createElement('div');
            box.className = 'aic-alert aic-alert-' + type;
            const title = box.appendChild(document.createElement('div'));
            title.className = 'aic-alert-title';
            title.innerHTML = '<i class="fas fa-' + alertIcons[type] + ' me-1"></i>';
            title.appendChild(document.createTextNode(L[type]));
            while (quote.firstChild) box.appendChild(quote.firstChild);
            quote.replaceWith(box);
        });
    }

    // A bar above each code block, with its language and the copy button:
    // outside the <pre>, so it neither covers the code nor scrolls with it.
    function codeBlocks(el) {
        el.querySelectorAll('pre').forEach(function (pre) {
            const code = pre.querySelector('code');
            const language = code ? (code.className.match(/language-(\S+)/) || [])[1] : null;
            if (language === 'mermaid') return;
            const head = document.createElement('div');
            head.className = 'aic-code-head';
            head.appendChild(document.createElement('span')).textContent = language || '';
            const button = head.appendChild(document.createElement('button'));
            button.type = 'button';
            button.className = 'btn btn-sm btn-outline-secondary';
            button.innerHTML = '<i class="fas fa-copy me-1"></i>';
            button.appendChild(document.createTextNode(L.copy));
            button.addEventListener('click', function () {
                copyValueToClipboard(pre.textContent.replace(/\n$/, ''), L.copied);
            });
            const wrap = document.createElement('div');
            wrap.className = 'aic-code';
            pre.replaceWith(wrap);
            wrap.append(head, pre);
        });
    }

    // Drawn one after the other, as the event report reader does; a diagram
    // mermaid cannot draw stays as its source.
    let diagrams = 0;
    function mermaidDiagrams(el) {
        const blocks = el.querySelectorAll('pre > code.language-mermaid');
        if (!blocks.length) return;
        script(root.dataset.mermaidUrl, 'mermaid').then(function (mermaid) {
            const dark = document.documentElement.getAttribute('data-misp-mode') === 'dark';
            mermaid.initialize({startOnLoad: false, theme: dark ? 'dark' : 'neutral'});
            return Array.prototype.reduce.call(blocks, function (chain, code) {
                return chain.then(function () {
                    return mermaid.mermaidAPI.render(root.id + '-mermaid-' + (++diagrams), code.textContent).then(function (out) {
                        const figure = document.createElement('div');
                        figure.className = 'aic-mermaid';
                        figure.innerHTML = out.svg;
                        code.parentNode.replaceWith(figure);
                    }, function () {});
                });
            }, Promise.resolve());
        }, function () {});
    }

    const blocks = root.querySelectorAll('[data-aic-md]');
    script(root.dataset.markdownUrl, 'markdownit').then(function (factory) {
        const md = factory('default');
        blocks.forEach(function (el) {
            el.innerHTML = md.render(el.textContent);
            links(el);
            alerts(el);
            el.querySelectorAll('table').forEach(function (table) {
                const wrap = document.createElement('div');
                wrap.className = 'table-responsive';
                table.replaceWith(wrap);
                wrap.appendChild(table);
            });
            codeBlocks(el);
            el.hidden = false;
            mermaidDiagrams(el);
        });
    }).catch(function () {
        blocks.forEach(function (el) {
            el.classList.add('aic-md-raw');
            el.hidden = false;
        });
    });
})();
</script>
<?php endif; ?>
