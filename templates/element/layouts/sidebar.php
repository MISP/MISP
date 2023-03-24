<?php
    $bookmarkIncluded = $loggedUser->user_settings_by_name_with_fallback['ui.sidebar.include_bookmarks']['value'];
?>
<div class="sidebar-wrapper d-flex flex-column">
    <div class="sidebar-scroll">
        <div class="sidebar-content">
            <ul id="sidebar-elements" class="sidebar-elements">
                <?php foreach ($menu as $category => $categorized) : ?>
                    <?php if ($category == '__bookmarks') : ?>
                        <?php if ($bookmarkIncluded) : ?>
                            <?= $this->element('layouts/sidebar/category', ['label' => __('Bookmarks'), 'class' => 'bookmark-categ']) ?>
                            <?= $this->element('UserSettings/saved-bookmarks', [
                                'bookmarks' => $categorized,
                                'forSidebar' => true,
                            ]) ?>
                        <?php endif;  ?>
                    <?php else: ?>
                        <?= $this->element('layouts/sidebar/category', ['label' => $category]) ?>
                        <?php foreach ($categorized as $parentName => $parent) : ?>
                            <?= $this->element('layouts/sidebar/entry', [
                                'parentName' => $parentName,
                                'parent' => $parent,
                            ])
                            ?>
                        <?php endforeach; ?>
                    <?php endif; ?>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <span class="lock-sidebar align-self-center mt-auto w-100 d-none d-sm-block">
        <a type="button" class="btn-lock-sidebar btn btn-sm w-100"></a>
    </span>
</div>