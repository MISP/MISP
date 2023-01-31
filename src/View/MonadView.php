<?php
declare(strict_types=1);

/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link          https://cakephp.org CakePHP(tm) Project
 * @since         3.0.4
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 */
namespace App\View;

/**
 * A view class that supports rendering view file belonging to directories outside of the main application template folder.
 */
class MonadView extends AppView
{
    private $additionalTemplatePaths = [
        ROOT . '/libraries/default/InboxProcessors/templates/',
        ROOT . '/libraries/default/OutboxProcessors/templates/',
    ];

    protected function _paths(?string $plugin = null, bool $cached = true): array
    {
        $paths = parent::_paths($plugin, $cached);
        $paths = array_merge($paths, $this->additionalTemplatePaths);
        return $paths;
    }
}
