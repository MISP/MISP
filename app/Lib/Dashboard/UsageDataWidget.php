<?php
class UsageDataWidget
{
    public $title = 'Usage data';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 5;
    public $params = array();
    public $description = 'Shows usage data / statistics.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 3;

    public function handler($user, $options = array()){
        $this->User = ClassRegistry::init('User');

        $orgsCount = $this->User->Organisation->find('count');
        $localOrgsParams['conditions']['Organisation.local'] = 1;
        $localOrgsCount = $this->User->Organisation->find('count', $localOrgsParams);

        $thisMonth = strtotime('first day of this month');
        $this->Event = ClassRegistry::init('Event');
        $eventsCount = $this->Event->find('count', array('recursive' => -1));
        $eventsCountMonth = $this->Event->find('count', array('conditions' => array('Event.timestamp >' => $thisMonth), 'recursive' => -1));

        $this->Attribute = ClassRegistry::init('Attribute');
        $attributesCount = $this->Attribute->find('count', array('conditions' => array('Attribute.deleted' => 0), 'recursive' => -1));
        $attributesCountMonth = $this->Attribute->find('count', array('conditions' => array('Attribute.timestamp >' => $thisMonth, 'Attribute.deleted' => 0), 'recursive' => -1));
        $attributesPerEvent = round($attributesCount / $eventsCount);

        $this->Correlation = ClassRegistry::init('Correlation');
        $correlationsCount = $this->Correlation->find('count', array('recursive' => -1)) / 2;

        $proposalsCount = $this->Event->ShadowAttribute->find('count', array('recursive' => -1, 'conditions' => array('deleted' => 0)));

        $usersCount = $this->User->find('count', array('recursive' => -1));
        $usersCountPgp = $this->User->find('count', array('recursive' => -1, 'conditions' => array('User.gpgkey !=' => '')));
        $usersCountPgpPercentage = round(100* ($usersCountPgp / $usersCount), 1);
        $contributingOrgsCount = $this->Event->find('count', array('recursive' => -1, 'group' => array('Event.orgc_id')));
        $averageUsersPerOrg = round($usersCount / $localOrgsCount, 1);

        $this->Thread = ClassRegistry::init('Thread');
        $threadCount = $this->Thread->find('count', array('conditions' => array('Thread.post_count >' => 0), 'recursive' => -1));
        $threadCountMonth = $this->Thread->find('count', array('conditions' => array('Thread.date_created >' => date("Y-m-d H:i:s", $thisMonth), 'Thread.post_count >' => 0), 'recursive' => -1));

        $postCount = $this->Thread->Post->find('count', array('recursive' => -1));
        $postCountMonth = $this->Thread->Post->find('count', array('conditions' => array('Post.date_created >' => date("Y-m-d H:i:s", $thisMonth)), 'recursive' => -1));

        //Monhtly data is not added to the widget at the moment, could optionally add these later and give user choice?

        $statistics = array(
            array('title' => 'Events', 'value' => $eventsCount),
            array('title' => 'Attributes', 'value' => $attributesCount),
            array('title' => 'Attributes / event', 'value' => $attributesPerEvent),
            array('title' => 'Correlations', 'value' => $correlationsCount),
            array('title' => 'Active proposals', 'value' => $proposalsCount),
            array('title' => 'Users', 'value' => $usersCount),
            array('title' => 'Users with PGP keys', 'value' => $usersCountPgp . ' (' . $usersCountPgpPercentage . '%)'),
            array('title' => 'Organisations', 'value' => $orgsCount),
            array('title' => 'Local organisations', 'value' => $localOrgsCount),
            array('title' => 'Event creator orgs', 'value' => $contributingOrgsCount),
            array('title' => 'Average users / org', 'value' => $averageUsersPerOrg),
            array('title' => 'Discussions threads', 'value' => $threadCount),
            array('title' => 'Discussion posts', 'value' => $postCount)
        );
        if(!empty(Configure::read('Security.advanced_authkeys'))){
            $this->AuthKey = ClassRegistry::init('AuthKey');
            $authkeysCount = $this->AuthKey->find('count', array('recursive' => -1));
            $statistics[] = array('title' => 'Advanced authkeys', 'value' => $authkeysCount);
        }
        return $statistics;
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
