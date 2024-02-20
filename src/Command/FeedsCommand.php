<?php

namespace App\Command;

use App\Lib\Tools\LogExtendedTrait;
use App\Model\Entity\Job;
use Cake\Console\ConsoleIo;
use Cake\Core\Configure;
use Exception;

class FeedsCommand extends MISPCommand
{
    use LogExtendedTrait;

    protected $defaultTable = 'Feeds';

    /** @var \App\Model\Table\FeedsTable */
    protected $Feeds;

    protected $validActions = [
        'fetchFeed',
        'listFeeds',
        'viewFeed',
        'toggleFeed',
        'toggleFeedCaching',
        'loadDefaultFeeds',
        'cacheFeed',
    ];

    /** @var array */
    protected $usage = [
        'test' => 'bin/cake servers test `server_id`',
        'fetchIndex' => 'bin/cake servers fetchIndex `server_id`',
        'fetchFeed' => 'bin/cake servers `fetchFeed` `user_id` feed_id|all|csv|text|misp [job_id]',
        'pullAll' => 'bin/cake servers pullAll `user_id` [full|update]',
        'pull' => 'bin/cake servers pull `user_id` `server_id` [full|update]',
        'push' => 'bin/cake servers push `user_id` `server_id` [full|update] [job_id]',
        'pushAll' => 'bin/cake servers pushAll `user_id` [full|update]',
        'listFeeds' => 'bin/cake servers listFeeds [json|table]',
        'viewFeed' => 'bin/cake servers viewFeed `feed_id` [json|table]',
        'toggleFeed' => 'bin/cake servers toggleFeed `feed_id`',
        'toggleFeedCaching' => 'bin/cake servers toggleFeedCaching `feed_id`',
        'cacheServer' => 'bin/cake servers cacheServer `user_id` `server_id|all` [job_id]',
        'cacheServerAll' => 'bin/cake servers cacheServerAll `user_id` [job_id]',
        'cacheFeed' => 'bin/cake servers cacheFeed `user_id` [feed_id|all|csv|text|misp] [job_id]',
    ];

    public function fetchFeed($userId, $feedId, $jobId = null)
    {
        if (empty($userId) || empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $UsersTable = $this->fetchTable('Users');
        $user = $UsersTable->getAuthUser($userId, true);

        Configure::write('CurrentUserId', $userId);

        $JobsTable = $this->fetchTable('Jobs');

        if (empty($jobId)) {
            $jobId = $JobsTable->createJob($user->toArray(), Job::WORKER_DEFAULT, 'fetch_feeds', 'Feed: ' . $feedId, 'Starting fetch from Feed.');
        }
        if ($feedId === 'all') {
            $feedIds = $this->Feeds->find(
                'column',
                [
                    'fields' => ['id'],
                    'conditions' => ['enabled' => 1]
                ]
            )->toArray();
            $successes = 0;
            $fails = 0;
            foreach ($feedIds as $k => $feedId) {
                $JobsTable->saveProgress($jobId, 'Fetching feed: ' . $feedId, 100 * $k / count($feedIds));
                $result = $this->Feeds->downloadFromFeedInitiator($feedId, $user);
                if ($result) {
                    $successes++;
                } else {
                    $fails++;
                }
            }
            $message = 'Job done. ' . $successes . ' feeds pulled successfully, ' . $fails . ' feeds could not be pulled.';
            $JobsTable->saveStatus($jobId, true, $message);
            $this->io->out($message);
        } else {
            $feedEnabled = $this->Feeds->exists(
                [
                    'enabled' => 1,
                    'id' => $feedId,
                ]
            );
            if ($feedEnabled) {
                $result = $this->Feeds->downloadFromFeedInitiator($feedId, $user, $jobId);
                if (!$result) {
                    $JobsTable->saveStatus($jobId, false, 'Job failed. See error log for more details.');
                    $this->io->error('Job failed.');
                } else {
                    $JobsTable->saveStatus($jobId, true);
                    $this->io->out('Job done.');
                }
            } else {
                $message = "Feed with ID $feedId not found or not enabled.";
                $JobsTable->saveStatus($jobId, false, $message);
                $this->io->error($message);
            }
        }
    }

    public function listFeeds($outputStyle = 'json')
    {
        $fields = [
            'id' => 3,
            'source_format' => 10,
            'provider' => 15,
            'url' => 50,
            'enabled' => 8,
            'caching_enabled' => 7
        ];

        $feeds = $this->Feeds->find(
            'all',
            [
                'recursive' => -1,
                'fields' => array_keys($fields)
            ]
        );
        if ($outputStyle === 'table') {
            $this->io->out(str_repeat('=', 114));
            $this->io->out(
                sprintf(
                    '| %s | %s | %s | %s | %s | %s |',
                    str_pad('ID', $fields['id'], ' ', STR_PAD_RIGHT),
                    str_pad('Format', $fields['source_format'], ' ', STR_PAD_RIGHT),
                    str_pad('Provider', $fields['provider'], ' ', STR_PAD_RIGHT),
                    str_pad('Url', $fields['url'], ' ', STR_PAD_RIGHT),
                    str_pad('Fetching', $fields['enabled'], ' ', STR_PAD_RIGHT),
                    str_pad('Caching', $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
                ),
                1,
                ConsoleIo::NORMAL
            );
            $this->io->out(str_repeat('=', 114));
            foreach ($feeds as $feed) {
                $this->io->out(
                    sprintf(
                        '| %s | %s | %s | %s | %s | %s |',
                        str_pad($feed['id'], $fields['id'], ' ', STR_PAD_RIGHT),
                        str_pad($feed['source_format'], $fields['source_format'], ' ', STR_PAD_RIGHT),
                        str_pad(mb_substr($feed['provider'], 0, 13), $fields['provider'], ' ', STR_PAD_RIGHT),
                        str_pad(
                            mb_substr($feed['url'], 0, 48),
                            $fields['url'],
                            ' ',
                            STR_PAD_RIGHT
                        ),
                        $feed['enabled'] ?
                            '<info>' . str_pad(__('Yes'), $fields['enabled'], ' ', STR_PAD_RIGHT) . '</info>' :
                            str_pad(__('No'), $fields['enabled'], ' ', STR_PAD_RIGHT),
                        $feed['caching_enabled'] ?
                            '<info>' . str_pad(__('Yes'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT) . '</info>' :
                            str_pad(__('No'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
                    ),
                    1,
                    ConsoleIo::NORMAL
                );
            }
            $this->io->out(str_repeat('=', 114));
        } else {
            $this->outputJson($feeds);
        }
    }

    public function viewFeed($feedId = null, $outputStyle = 'json')
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $feed = $this->Feeds->get($feedId)->toArray();

        if (empty($feed)) {
            throw new Exception(__('Invalid feed.'));
        }
        if ($outputStyle === 'table') {
            $this->io->out(str_repeat('=', 114));
            foreach ($feed as $field => $value) {
                if (is_array($value)) {
                    $value = json_encode($value, JSON_PRETTY_PRINT);
                }
                $this->io->out(
                    sprintf(
                        '| %s | %s |',
                        str_pad($field, 20, ' ', STR_PAD_RIGHT),
                        str_pad($value ?? '', 87)
                    ),
                    1,
                    ConsoleIo::NORMAL
                );
            }
            $this->io->out(str_repeat('=', 114));
        } else {
            $this->outputJson($feed);
        }
    }

    public function toggleFeed($feedId = null)
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $feed = $this->Feeds->get($feedId);

        $feed['enabled'] = ($feed['enabled']) ? 0 : 1;
        if ($this->Feeds->save($feed)) {
            $this->io->out(__('Feed fetching {0} for feed {1}', ($feed['enabled'] ? __('enabled') : __('disabled')), $feed['id']));
        } else {
            $this->io->out(__('Could not toggle fetching for feed {0}', $feed['id']));
        }
    }

    public function toggleFeedCaching($feedId = null)
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $feed = $this->Feeds->get($feedId);

        $feed['caching_enabled'] = ($feed['caching_enabled']) ? 0 : 1;
        if ($this->Feeds->save($feed)) {
            $this->io->out(__('Feed caching {0} for feed {1}', ($feed['caching_enabled'] ? __('enabled') : __('disabled')), $feed['id']));
        } else {
            $this->io->out(__('Could not toggle caching for feed {0}', $feed['id']));
        }
    }

    public function loadDefaultFeeds()
    {
        $this->Feeds->load_default_feeds();
        $this->io->out(__('Default feed metadata loaded.'));
    }

    public function cacheFeed($userId = null, $scope = null, $jobId = null)
    {
        if (empty($userId) || empty($scope)) {
            $this->showActionUsageAndExit();
        }

        $user = $this->getUser($userId);

        $JobsTable = $this->fetchTable('Jobs');

        if (!empty($jobId)) {
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'cache_feeds', 'Feed: ' . $scope, 'Starting feed caching.');
        }
        try {
            $result = $this->Feeds->cacheFeedInitiator($user, $jobId, $scope);
        } catch (Exception $e) {
            $this->logException("Failed caching Feed: $scope", $e);
            $result = false;
        }

        if ($result === false) {
            $message = __('Job failed. See error logs for more details.');
            $JobsTable->saveStatus($jobId, false, $message);
        } else {
            $total = $result['successes'] + $result['fails'];
            $message = __(
                '{0} feed from {1} cached. Failed: {2}',
                $result['successes'],
                $total,
                $result['fails']
            );
            if ($result['fails'] > 0) {
                $message .= ' ' . __('See error logs for more details.');
            }
            $JobsTable->saveStatus($jobId, true, $message);
        }
        $this->io->out($message);
    }
}
