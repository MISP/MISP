<?php
$headerActions = [];
if ($this->Acl->canAccess('news', 'admin_index')) {
    $headerActions[] = [
        'type' => 'navigate',
        'label' => __('Manage news'),
        'icon' => 'pen-to-square',
        'url' => $baseurl . '/admin/news/index',
    ];
}
$this->set('headerTitle', __('News'));
$this->set('headerDescription', __('Announcements from the administrators of this instance.'));
$this->set('headerActions', $headerActions);
?>
<div class="container-fluid">
    <?php if ($hasUnreadNews): ?>
        <div class="alert alert-success d-flex justify-content-between align-items-center flex-wrap gap-2">
            <span><i class="fas fa-bell me-2"></i><?= __('You have unread news.') ?></span>
            <a class="btn btn-success btn-sm" href="<?= h(isset($homepage['path']) ? $homepage['path'] : $homepage) ?>"><?= __('Continue to homepage') ?></a>
        </div>
    <?php endif; ?>

    <?php if (empty($newsItems)): ?>
        <p class="text-muted"><?= __('There is no news yet.') ?></p>
    <?php endif; ?>

    <?php foreach ($newsItems as $news): ?>
        <article class="card shadow-sm mb-3<?= $news['News']['new'] ? ' border-warning' : '' ?>">
            <div class="card-body">
                <h2 class="h5 card-title mb-1">
                    <?php if ($news['News']['new']): ?>
                        <span class="badge text-bg-warning me-1"><?= __('New') ?></span>
                    <?php endif; ?>
                    <?= h($news['News']['title']) ?>
                </h2>
                <p class="text-muted small mb-3">
                    <i class="fas fa-calendar me-1 opacity-50"></i><?= $this->Time->time($news['News']['date_created']) ?>
                    <?php if (!empty($news['User']['email'])): ?>
                        <i class="fas fa-user ms-3 me-1 opacity-50"></i><?= h($news['User']['email']) ?>
                    <?php endif; ?>
                </p>
                <div class="news-message"><?= h($news['News']['message']) ?></div>
            </div>
        </article>
    <?php endforeach; ?>

    <?php if (!empty($newsItems)): ?>
        <?= $this->element('genericElementsBS5/IndexTable/pagination') ?>
    <?php endif; ?>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => ['markdown-it'],
]) ?>
<script>
    (function () {
        var md = window.markdownit('default');
        md.disable(['image']);
        document.querySelectorAll('.news-message').forEach(function (el) {
            el.innerHTML = md.render(el.textContent);
        });
    })();
</script>
