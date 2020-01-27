<?php
    foreach ($data as $controller => $controllerData) {
        echo sprintf(
            '<div class="bold blue">%s</div>',
            h($controller)
        );
        foreach ($controllerData as $action => $userData) {
            echo sprintf(
                '<div class="bold" style="margin-left:8px">%s</div>%s',
                h($action),
                sprintf(
                    '<div style="margin-left:16px;"><span class="bold">%s</span>: %s %s</div>',
                    __('Total'),
                    sprintf(
                        '%s Users (%s requests)',
                        sprintf(
                            '<span class="bold red">%s</span>',
                            count($userData) -1
                        ),
                        sprintf(
                            '<span class="red">%s</span>',
                            h($userData['total'])
                        )
                    ),
                    sprintf(
                        '<i class="fas fa-plus-circle" role="button" aria-label="%s" data-toggle="collapse" data-target="#deprecationDetails%s%s"></i>',
                        __('View details on the usage of %s on the %s controller', h($action), h($controller)),
                        h($controller),
                        h($action)
                    )
                )
            );
            $userDataDiv = '';
            foreach ($userData as $userId => $count) {
                if ($userId !== 'total') {
                    $userDataDiv .= sprintf(
                        '<div style="margin-left:24px;"><a href="%s" aria-label="%s">%s</a>: %s</div>',
                        $baseurl . '/admin/users/view/' . h($userId),
                        __('View user ID ', h($userId)),
                        __('User #%s', h($userId)),
                        h($count)
                    );
                }
            }
            echo sprintf(
                '<div id="deprecationDetails%s%s" data-toggle="collapse" class="collapse">%s</div>',
                h($controller),
                h($action),
                $userDataDiv
            );
        }
    }

?>
