<?php
use Cake\Utility\Inflector;
use Cake\Routing\Router;
?>

<table class="table">
    <thead>
        <tr>
            <th scope="col"><?= __('Field name') ?></th>
            <th scope="col"><?= __('Conflict') ?></th>
            <th scope="col"><?= __('Conflicting entities') ?></th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($templateStatus['conflicts'] as $fieldName => $fieldConflict) : ?>
            <?php foreach ($fieldConflict['conflicts'] as $conflict) : ?>
                <tr>
                    <th scope="row"><?= h($fieldName) ?></th>
                    <td>
                        <?= h($conflict) ?>
                    </td>
                    <td>
                        <?php
                        foreach ($fieldConflict['conflictingEntities'] as $i => $id) {
                            if ($i > 0) {
                                echo ', ';
                            }
                            if ($i > 10) {
                                echo sprintf('<span class="fw-light fs-7">%s</span>', __('{0} more', count($fieldConflict['conflictingEntities'])-$i));
                                break;
                            }
                            $url = Router::url([
                                'controller' => Inflector::pluralize($templateStatus['existing_template']->scope),
                                'action' => 'view',
                                $id
                            ]);
                            echo sprintf('<a href="%s" target="_blank">%s</a>', $url, __('{0} #{1}', h(Inflector::humanize($templateStatus['existing_template']->scope)),  h($id)));
                        }
                        ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php endforeach; ?>
    </tbody>
</table>