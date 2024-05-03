<div class="index">
    <h2><?= __("Latest news") ?></h2>
    <?php if ($hasUnreadNews): ?>
    <div class="alert alert-success">
        <p><?= __('You have unread news.') ?></p>
        <a class="btn btn-success" href="<?= isset($homepage['path']) ? $homepage['path'] : $homepage ?>"><?= __('Continue to homepage') ?></a>
    </div>
    <?php endif; ?>

    <div class="pagination">
        <ul>
            <?php
            $pagination = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $pagination .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            $pagination .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $pagination;
            ?>
        </ul>
    </div>

    <?php foreach ($newsItems as $news): ?>
        <h3 style="margin-bottom: 5px; font-size: 22px"><?php if ($news['News']['new']): ?><span class="label label-warning"><?= __('New') ?></span><?php endif; ?> <?= h($news['News']['title']) ?></h3>
        <p><?= __('Published at %s%s', $this->Time->time($news['News']['date_created']), $news['User']['email'] ? __(' by %s', $news['User']['email']) : '') ?></p>
        <div class="md" style="font-size: 14px; margin-bottom: 32px; "><?= h($news['News']['message']) ?></div>
    <?php endforeach; ?>

    <p>
        <?= $this->Paginator->counter(array(
            'format' => __('Page {:page} of {:pages}, showing {:current} articles out of {:count} total, starting on article {:start}, ending on {:end}')
        ));
        ?>
    </p>
    <div class="pagination">
        <ul>
            <?= $pagination ?>
        </ul>
    </div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => [
        'markdown-it',
    ],
]);
?>
<script>
    var md = window.markdownit('default');
    md.disable(['image'])
    $('.md').each(function (_, el) {
        var $el = $(el);
        $el.html(md.render($el.text()));
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'news', 'menuItem' => 'index']);