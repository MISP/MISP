<?php
if (!$isSiteAdmin) exit();
if ($updateProgress['update_prog_cur'] !== '' && $updateProgress['update_prog_cur'] !== '') {
    $percentage = $updateProgress['update_prog_cur'] / $updateProgress['update_prog_tot']*100;
} else {
    $percentage = 100;
}
?>
<div style="width: 50%;margin: 0 auto;">
    <h2><?php echo(__('Update progress'));?></h2>
    <div class="advancedUpdateBlock" style="max-width: 800px;">
        
        <div class="progress progress-striped" style="max-width:800px;">
            <div class="bar" style="width: <?php echo h($percentage);?>%;"><?php echo h($percentage);?>%</div>
        </div>

        <table class="table table-bordered table-stripped">
            <thead>
                <tr>
                    <th></th>
                    <th>Update command</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($updateProgress['update_prog_msg'] !== ''): ?>
                    <?php foreach($updateProgress['update_prog_msg'] as $i => $msg): ?>
                        <tr>
                            <td><?php echo $i<= $updateProgress['update_prog_cur'] ? 'X' : ''; ?></td>
                            <td><?php echo $msg; ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

    </div>
</div>
