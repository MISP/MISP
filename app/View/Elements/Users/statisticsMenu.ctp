<div class="btn-toolbar">
    <div class="btn-group">
        <?php 
            foreach ($pages as $key => $value):
        ?>
                <a class="btn <?php echo $page == $key ? 'btn-primary' : 'btn-inverse'?> qet" href="<?php echo $baseurl . '/users/statistics/' . h($key); ?>"><?php echo h($value); ?></a>
        <?php 
            endforeach;
        ?>
    </div>
</div>
