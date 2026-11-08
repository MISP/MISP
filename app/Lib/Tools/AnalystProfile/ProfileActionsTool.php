<?php

/**
 * The writes a reader may start on one profile: the index's row menu and
 * the view's action card both draw them from here.
 *
 * A profile its scope owns is used by switching it on and dropped by
 * switching it off; anybody else's is chosen and unchosen. Each route
 * answers an ajax GET with its confirmation modal, so every entry is
 * opened with `openModal()`.
 */
class ProfileActionsTool
{
    /**
     * @param array $profile A row of AnalystProfile::indexFor()
     * @param array $may `org` to choose for the organisation, `instance` to
     *                   choose for the instance, `fork_org` to fork to it
     * @return array `use`, `fork`, `share` and `delete`, each a list of
     *               `icon`, `label`, `short` (a tile's label), `url` (a
     *               route array), and `disabled`
     *               for a state that is shown rather than offered
     */
    public static function writes(array $profile, array $may)
    {
        $id = $profile['id'];
        $selectedBy = $profile['selected_by'];
        $entry = function ($icon, $label, array $url, $short = null) {
            return array('icon' => $icon, 'label' => $label, 'url' => $url,
                'short' => $short === null ? $label : $short,
                'disabled' => false);
        };
        $writes = array(
            'use' => array(),
            'fork' => array(),
            'share' => array(),
            'delete' => array(),
        );

        if ($profile['scope_rank'] === 3) {
            $writes['use'][] = $profile['enabled']
                ? $entry('user-xmark', __('Stop using for me'),
                    array('action' => 'disable', $id), __('Stop using'))
                : $entry('user-check', __('Use for me'),
                    array('action' => 'enable', $id));
        } elseif (in_array('user', $selectedBy, true)) {
            $writes['use'][] = $entry('user-xmark', __('Stop using for me'),
                array('action' => 'deselect', '?' => array('scope' => 'user')),
                __('Stop using'));
        } elseif (!empty($profile['selectable'])) {
            $writes['use'][] = $entry('user-check', __('Use for me'),
                array('action' => 'select', $id,
                    '?' => array('scope' => 'user')));
        }

        if ($profile['scope_rank'] === 2 && $profile['editable']) {
            $writes['use'][] = $profile['enabled']
                ? $entry('building-circle-xmark',
                    __('Stop using for my organisation'),
                    array('action' => 'disable', $id), __('Stop for org'))
                : $entry('building-circle-check', __('Use for my organisation'),
                    array('action' => 'enable', $id), __('Use for org'));
        } elseif (in_array('org', $selectedBy, true) && !empty($may['org'])) {
            $writes['use'][] = $entry('building-circle-xmark',
                __('Stop using for my organisation'),
                array('action' => 'deselect', '?' => array('scope' => 'org')),
                __('Stop for org'));
        } elseif (!empty($profile['selectable_for_org'])) {
            $writes['use'][] = $entry('building-circle-check',
                __('Use for my organisation'),
                array('action' => 'select', $id,
                    '?' => array('scope' => 'org')), __('Use for org'));
        }

        // The instance always names a profile, so it is pointed elsewhere rather than stopped.
        if (!empty($may['instance'])
            && in_array('instance', $selectedBy, true)
        ) {
            $writes['use'][] = array('icon' => 'server',
                'label' => __('Runs on this instance'), 'url' => null,
                'short' => __('Runs here'),
                'disabled' => true);
        } elseif (!empty($may['instance']) && !empty($profile['enabled'])
            && (!empty($profile['default']) || !empty($profile['shared']))
        ) {
            $writes['use'][] = $entry('server', __('Run on this instance'),
                array('action' => 'select', $id,
                    '?' => array('scope' => 'instance')), __('Run here'));
        }

        if (!$profile['in_force'] || !empty($profile['default'])) {
            $writes['fork'][] = $entry('code-branch', __('Fork to me'),
                array('action' => 'fork', $id));
            if (!empty($may['fork_org'])) {
                $writes['fork'][] = $entry('code-branch',
                    __('Fork to my organisation'),
                    array('action' => 'fork', $id,
                        '?' => array('for_org' => 1)));
            }
        }

        if (!empty($profile['can_share'])) {
            $writes['share'][] = empty($profile['shared'])
                ? $entry('share-nodes', __('Share with everyone'),
                    array('action' => 'share', $id))
                : $entry('share-nodes', __('Stop sharing'),
                    array('action' => 'unshare', $id));
        }

        if ($profile['editable'] && empty($profile['default'])) {
            $writes['delete'][] = $entry('trash', __('Delete'),
                array('action' => 'delete', $id));
        }
        return $writes;
    }
}
