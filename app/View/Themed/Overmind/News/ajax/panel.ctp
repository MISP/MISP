<?php
/**
 * The news panel's list (Elements/news_panel.ctp), one page at a time, laid
 * out like a conversation: a rule with the day between days, the author over
 * each card. news-panel.js appends the next page in place of the "older"
 * button, and drops its first rule when that day is already on screen.
 */
$canEdit = $this->Acl->canAccess('news', 'edit');
$canDelete = $this->Acl->canAccess('news', 'deleteSelection');
$page = (int)$this->Paginator->current();

$today = date('Y-m-d');
$yesterday = date('Y-m-d', strtotime('-1 day'));
$dayLabel = function ($timestamp, $day) use ($today, $yesterday) {
    if ($day === $today) {
        return __('Today');
    }
    if ($day === $yesterday) {
        return __('Yesterday');
    }
    return date(date('Y', $timestamp) === date('Y') ? 'l j F' : 'j F Y', $timestamp);
};
$previousDay = null;
?>
<?php if (empty($newsItems) && $page <= 1): ?>
    <div class="sp-empty">
        <i class="fas fa-newspaper" aria-hidden="true"></i>
        <strong><?= __('There is no news yet.') ?></strong>
        <p><?= __('Announcements from the administrators of this instance show up here.') ?></p>
    </div>
<?php endif; ?>
<?php foreach ($newsItems as $news): ?>
    <?php
    $created = (int)$news['News']['date_created'];
    $day = date('Y-m-d', $created);
    if (!empty($news['User']['email'])) {
        $author = $news['User']['email'];
    } elseif (empty($news['News']['user_id'])) {
        $author = __('Anonymous');
    } else {
        $author = __('Deleted user');
    }
    $isNew = !empty($news['News']['new']);
    ?>
    <?php if ($day !== $previousDay): ?>
        <div class="nw-day" role="separator" data-news-day="<?= h($day) ?>">
            <span><?= h($dayLabel($created, $day)) ?></span>
        </div>
        <?php $previousDay = $day; ?>
    <?php endif; ?>
    <article class="nw-msg<?= $isNew ? ' is-new' : '' ?>" tabindex="-1" aria-labelledby="nw-msg-<?= h($news['News']['id']) ?>">
        <div class="nw-msg-by">
            <span class="nw-msg-who<?= empty($news['User']['email']) ? ' is-muted' : '' ?>" title="<?= h($author) ?>"><?= h($author) ?></span>
            <span class="nw-msg-when" tabindex="0" data-news-when
                  title="<?= h(date('Y-m-d H:i', $created)) ?>"
                  aria-label="<?= h(__('Posted %s', date('Y-m-d H:i', $created))) ?>">
                <i class="far fa-clock" aria-hidden="true"></i>
            </span>
        </div>
        <div class="nw-card">
            <h3 class="nw-card-title" id="nw-msg-<?= h($news['News']['id']) ?>">
                <?php if ($isNew): ?>
                    <span class="nw-new"><?= __('New') ?></span>
                <?php endif; ?>
                <?= h($news['News']['title']) ?>
            </h3>
            <div class="nw-card-body" data-news-markdown><?= h($news['News']['message']) ?></div>
            <?php if ($canEdit || $canDelete): ?>
                <div class="nw-card-acts">
                    <?php if ($canEdit): ?>
                        <button type="button" class="sp-tool" data-sp-modal="<?= h($baseurl . '/news/edit/' . $news['News']['id']) ?>"
                                title="<?= __('Edit') ?>" aria-label="<?= __('Edit') ?>">
                            <i class="fas fa-pen-to-square" aria-hidden="true"></i>
                        </button>
                    <?php endif; ?>
                    <?php if ($canDelete): ?>
                        <button type="button" class="sp-tool sp-tool-danger" data-sp-modal="<?= h($baseurl . '/news/deleteSelection/' . $news['News']['id']) ?>"
                                data-sp-modal-size="md" title="<?= __('Delete') ?>" aria-label="<?= __('Delete') ?>">
                            <i class="fas fa-trash" aria-hidden="true"></i>
                        </button>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </article>
<?php endforeach; ?>
<?php if ($this->Paginator->hasNext()): ?>
    <button type="button" class="btn btn-sm btn-outline-secondary sp-more" data-news-more="<?= $page + 1 ?>">
        <i class="fas fa-angles-down me-1" aria-hidden="true"></i><?= __('Show older news') ?>
    </button>
<?php endif; ?>
