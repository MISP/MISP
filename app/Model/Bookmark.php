<?php
App::uses('AppModel', 'Model');

class Bookmark extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'user_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'org_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'url' => array(
            'url' => array(
                'rule' => array('validateURL'),
                'message' => 'Please enter a valid base-url.'
            )
        ),
    );

    public $belongsTo = [
        'User',
        'Organisation' => [
                'className' => 'Organisation',
                'foreignKey' => 'org_id'
        ],
    ];

    public $current_user = null;

    public function beforeValidate($options = [])
    {
        if (empty($this->data['Bookmark'])) {
            $this->data = ['Bookmark' => $this->data];
        }
        if (empty($this->id)) {
            $this->data['Bookmark']['org_id'] = $this->current_user['Organisation']['id'];
            $this->data['Bookmark']['user_id'] = $this->current_user['id'];
        }
        if (empty($this->current_user['Role']['perm_site_admin'])) {
            $this->data['Bookmark']['org_id'] = $this->current_user['Organisation']['id']; // Only site-admins can create Bookmarks for other orgs.
        }
        if (empty($this->current_user['Role']['perm_admin'])) {
            $this->data['Bookmark']['exposed_to_org'] = 0; // Only org-admins can create Bookmarks for their own org.
        }
        return true;
    }

    public function getBookmarksForUser(array $user): array
    {
        $bookmarks = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'OR' => [
                    'Bookmark.user_id' => $user['id'],
                    'AND' => [
                        'Bookmark.org_id' => $user['Organisation']['id'],
                        'Bookmark.exposed_to_org' => true,
                    ],
                ],
            ]
        ]);
        return $bookmarks;
    }

    public function validateURL($check)
    {
        $this->Server = ClassRegistry::init('Server');
        $check = array_values($check);
        $check = $check[0];
        return $this->Server->testURL($check);
    }

    public function mayModify($user, $bookmark_id)
    {
        $bookmark = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Bookmark.id' => $bookmark_id]
        ]);
        if (empty($bookmark)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!empty($user['Role']['perm_admin'])) {
            if ($user['org_id'] == $bookmark['Bookmark']['org_id']) {
                return true;
            }
        }
        if ($user['id'] === $bookmark['Bookmark']['user_id']) {
            return true;
        }
        return false;
    }

    public function mayView($user, $bookmark_id)
    {
        $bookmark = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Bookmark.id' => $bookmark_id]
        ]);
        if (empty($bookmark)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($user['id'] === $bookmark['Bookmark']['user_id']) {
            return true;
        }
        if ($user['org_id'] == $bookmark['Bookmark']['org_id'] && !empty($bookmark['Bookmark']['exposed_to_org'])) {
            return true;
        }
        return false;
    }

    // same as mayView, but with returning false if the user is not an org admin
    public function mayViewUser($user, $bookmark_id)
    {
        $bookmark = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Bookmark.id' => $bookmark_id]
        ]);
        if (empty($bookmark)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($user['id'] === $bookmark['Bookmark']['user_id']) {
            return true;
        }
        if ($user['Role']['perm_admin'] && $user['org_id'] == $bookmark['Bookmark']['org_id'] && !empty($bookmark['Bookmark']['exposed_to_org'])) {
            return true;
        }
        return false;
    }
}
