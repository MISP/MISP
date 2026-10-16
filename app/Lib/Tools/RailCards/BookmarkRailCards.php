<?php
App::uses('RailCard', 'Tools/RailCards');

/**
 * Rail cards for a bookmark. $bookmark is BookmarksController::view's find,
 * with User only when the viewer may see who owns it.
 */
class BookmarkRailCards
{
    const OTHERS_LIMIT = 6;

    /**
     * Who sees the bookmark in their menu.
     *
     * @param array $bookmark
     * @return array
     */
    public function audience(array $bookmark)
    {
        $b = $bookmark['Bookmark'];
        $orgName = $bookmark['Organisation']['name'] ?? '';
        $items = [];
        if (!empty($bookmark['User']['email'])) {
            $items[] = ['label' => __('Owner'), 'value' => $bookmark['User']['email']];
        }
        if (!empty($b['exposed_to_org'])) {
            $members = ClassRegistry::init('User')->find('count', [
                'recursive' => -1,
                'conditions' => ['User.org_id' => $b['org_id'], 'User.disabled' => 0],
            ]);
            $items[] = ['label' => __('Organisation'), 'value' => $orgName];
            return RailCard::status(
                'bookmark-audience',
                __('Audience'),
                'fas fa-users',
                'info',
                __n('Shared with the %s member of its organisation.', 'Shared with the %s members of its organisation.', $members, number_format($members)),
                $items
            );
        }
        return RailCard::status(
            'bookmark-audience',
            __('Audience'),
            'fas fa-user-lock',
            'muted',
            __('Private: only its owner sees it.'),
            $items
        );
    }

    /**
     * The viewer's other bookmarks, theirs and those their organisation
     * shares.
     *
     * @param array $user
     * @param array $bookmark
     * @param array $bookmarks Bookmark::getBookmarksForUser($user)
     * @return array
     */
    public function others(array $user, array $bookmark, array $bookmarks)
    {
        $rows = [];
        $listed = false;
        foreach ($bookmarks as $other) {
            $o = $other['Bookmark'];
            if ((int)$o['id'] === (int)$bookmark['Bookmark']['id']) {
                $listed = true;
                continue;
            }
            $host = parse_url((string)$o['url'], PHP_URL_HOST);
            $rows[] = [
                'label' => $o['name'],
                'href' => '/bookmarks/view/' . $o['id'],
                'icon' => 'fas fa-bookmark',
                'meta' => [$host ?: (string)$o['url']],
                'badge' => (int)$o['user_id'] !== (int)$user['id']
                    ? ['label' => __('Shared'), 'tone' => 'info']
                    : null,
            ];
        }
        $count = count($rows);
        return RailCard::rows(
            'bookmark-others',
            __('Other bookmarks'),
            'fas fa-bookmark',
            array_slice($rows, 0, self::OTHERS_LIMIT),
            $count > self::OTHERS_LIMIT
                ? ['label' => __('All %s bookmarks', number_format($count + ($listed ? 1 : 0))), 'href' => '/bookmarks/index']
                : null,
            ['empty' => $listed ? __('This is your only bookmark.') : __('You have no bookmark of your own.')]
        );
    }
}
