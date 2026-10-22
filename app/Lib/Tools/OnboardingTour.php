<?php

/**
 * Step catalogue for the Overmind onboarding tour.
 *
 * Structure: a section maps to a job a given role actually does. `general`
 * and `investigate` are for everyone; reporting and building out events need
 * the right to create them; `investigate-value` walks through the analysis
 * tools reached from a value; the last three mirror the Data models, Sync and
 * Administration menus. Each is gated on the permissions it needs, which
 * means a read-only analyst gets a short tour and a site admin gets all of
 * it. Each section is split into named groups (sub-sections) that can be
 * skipped or replayed on their own.
 *
 * Section keys
 *  - id, title, icon, summary
 *  - colour      Accent for the launcher card, named as an Overmind
 *                palette token (primary, tag, galaxy, …). onboarding.css
 *                maps the name to the token and carries the fallback, so
 *                no colour value is ever spelled out here.
 *  - requires    [controller, action] ACL gate for the whole section.
 *  - onDemand    Left out of the full tour (the first-login run and "Start
 *                the full tour"); only played when picked in the launcher.
 *  - groups      Ordered sub-sections, each [id, title, requires?, steps].
 *
 * Step keys
 *  - anchor      CSS selector to spotlight. Omit for a centred card. A
 *                selector list is allowed when either of two controls may be
 *                on screen (publish / unpublish).
 *  - title       Short heading.
 *  - body        HTML body. Authored here, so limited markup is allowed.
 *  - placement   Preferred side: top | bottom | left | right. The engine
 *                flips and clamps this to fit the viewport.
 *  - page        Path the step lives on. The engine navigates there. Must be
 *                a BS5-migrated page (see OvermindPages) or the tour assets
 *                are not loaded on arrival and the tour cannot resume.
 *  - pageMatch   Regex the current path must satisfy. Used for pages whose
 *                URL is not known ahead of time (an event id, say). With no
 *                `page` to navigate to, the tour docks and waits.
 *  - skipIf      Regex; skip the step when the current path already matches.
 *                Lets a group that normally starts by opening an event be
 *                replayed on its own without derailing the full run, which
 *                arrives already sitting on one.
 *  - skipUnless  Regex; skip the step unless the current path matches. For
 *                steps about a record the user was asked to open: an empty
 *                list leaves nothing to open, and nothing to wait for.
 *  - openMenu    Hold the navbar menus around the anchor open for the step —
 *                they otherwise only open on hover — and unfold the navbar
 *                when a narrow window has folded it behind its toggler.
 *  - waitingText Copy for the dock while waiting on `pageMatch`.
 *  - advance     'button' (default); 'click' to require the real click;
 *                'modal' to wait until #mainModal closes — the user saves
 *                the form or discards it, whichever way it goes.
 *  - interactive While the step is up the page only answers inside its
 *                anchor (or the selector given here); everything else is
 *                held back so a stray click cannot open a dialog under the
 *                spotlight. Set it on steps that ask the user to fill in.
 *  - closeModal  Dismiss #mainModal before rendering; use when a step points
 *                back at the page behind a dialog the tour just opened.
 *  - optional    Skip silently when the anchor never materialises.
 *  - requires    [controller, action] gate evaluated against the user's ACL.
 */
class OnboardingTour
{
    /** Path fragment of any single event view, whichever route was used. */
    const EVENT_VIEW_MATCH = '^/events/(view2|view)/[0-9]+';

    const VALUE_VIEW_MATCH = '^/values/view/[^/]+';

    const GRAPH_VIEW_MATCH = '^/(analyst_graphs|analystGraphs)/view/';

    /** Detail pages the Data models and Sync sections open from a list. */
    const TAXONOMY_VIEW = '^/taxonomies/view/[0-9]+';
    const GALAXY_VIEW = '^/galaxies/view/[0-9]+';
    const CLUSTER_VIEW = '^/galaxy_clusters/view/[0-9]+';
    const EVENT_TEMPLATE_VIEW = '^/event_templates/view/[0-9]+';
    const OBJECT_TEMPLATE_VIEW =
        '^/(objectTemplates|object_templates)/view/[0-9]+';
    const SHARING_GROUP_VIEW = '^/(SharingGroups|sharing_groups)/view/[0-9]+';

    /** The settings page rewrites its URL to the area on screen. */
    const SETTINGS_PAGE = '^/servers/serverSettings';

    /**
     * Build the catalogue, dropping anything the user cannot reach.
     *
     * Gates are ACL lookups rather than raw permission flags, which keeps this
     * honest with the rest of MISP and means a site admin passes every one of
     * them without needing a special case.
     *
     * @param callable $canAccess fn(string $controller, string $action): bool
     * @param int|null $orgId The user's organisation, to land editing groups
     *                        on events they may actually change.
     * @return array
     */
    public static function sections(callable $canAccess, $orgId = null)
    {
        $ownEvents = empty($orgId)
            ? '/events/index'
            : '/events/index/searchorg:' . (int)$orgId;

        $sections = [
            self::general(),
            self::investigate(),
            self::reportIncident(),
            self::buildEvent($ownEvents),
            self::dataModels(),
            self::investigateValue(),
            self::sync(),
            self::administration(),
        ];

        $result = [];
        foreach ($sections as $section) {
            // A section-level gate drops the whole section rather than
            // hollowing it out: a user who cannot create events should not be
            // walked through a creation form they will never be shown.
            if (!self::passes($section, $canAccess)) {
                continue;
            }
            unset($section['requires']);

            $steps = [];
            $groups = [];
            foreach ($section['groups'] as $group) {
                if (!self::passes($group, $canAccess)) {
                    continue;
                }
                $groupSteps = [];
                foreach ($group['steps'] as $step) {
                    if (!self::passes($step, $canAccess)) {
                        continue;
                    }
                    unset($step['requires']);
                    // Flattened so the engine keeps one linear index per
                    // section; the group tag is what drives the sub-section
                    // label and the "skip this part" control.
                    $step['group'] = $group['title'];
                    $step['groupId'] = $group['id'];
                    $groupSteps[] = $step;
                }
                if (empty($groupSteps)) {
                    continue;
                }
                $groups[] = [
                    'id' => $group['id'],
                    'title' => $group['title'],
                    'count' => count($groupSteps),
                ];
                $steps = array_merge($steps, $groupSteps);
            }

            if (empty($steps)) {
                continue;
            }
            unset($section['groups']);
            $section['steps'] = $steps;
            $section['groups'] = $groups;
            $result[] = $section;
        }

        return self::appendClosingStep($result);
    }

    /**
     * @param array $item Section, group or step carrying an optional gate.
     * @param callable $canAccess
     * @return bool
     */
    private static function passes(array $item, callable $canAccess)
    {
        if (empty($item['requires'])) {
            return true;
        }
        list($controller, $action) = $item['requires'];
        return (bool)$canAccess($controller, $action);
    }

    /**
     * First step of a group that works on an event. Replayed on its own it
     * opens one from the list; reached from the previous group the user is
     * already sitting on one, so it is skipped.
     *
     * @param string $page
     * @param string $title
     * @param string $body
     * @return array
     */
    private static function openEventStep($page, $title, $body)
    {
        return [
            'page' => $page,
            'anchor' => 'a[href*="/events/view"]',
            'placement' => 'right',
            'advance' => 'click',
            'optional' => true,
            'skipIf' => self::EVENT_VIEW_MATCH,
            'title' => $title,
            'body' => '<p>' . $body . '</p>',
        ];
    }

    /**
     * Close the full tour on whichever of its sections survived filtering
     * last, so every role gets a proper ending instead of stopping mid-topic.
     *
     * @param array $sections
     * @return array
     */
    private static function appendClosingStep(array $sections)
    {
        $lastIndex = null;
        foreach ($sections as $i => $section) {
            if (empty($section['onDemand'])) {
                $lastIndex = $i;
            }
        }
        if ($lastIndex === null) {
            return $sections;
        }
        $last = $sections[$lastIndex];
        $lastStep = end($last['steps']);

        $last['steps'][] = [
            'title' => __('That is the tour'),
            'body' => '<p>' . __('You have seen the parts of MISP your '
                . 'account has access to.') . '</p><p>' . __('Any section, or '
                . 'a single part of one, can be replayed from <strong>your '
                . 'account menu &rarr; Replay the tutorial</strong>.')
                . '</p>',
            'group' => $lastStep['group'],
            'groupId' => $lastStep['groupId'],
        ];
        foreach ($last['groups'] as $i => $group) {
            if ($group['id'] === $lastStep['groupId']) {
                $last['groups'][$i]['count']++;
            }
        }
        $sections[$lastIndex] = $last;
        return $sections;
    }

    /* ------------------------------------------------------------------ */
    /* 1. General — everyone                                               */
    /* ------------------------------------------------------------------ */

    private static function general()
    {
        return [
            'id' => 'general',
            'title' => __('Getting around'),
            'icon' => 'fas fa-compass',
            'colour' => 'primary',
            'summary' => __('The navigation bar, the page header and the '
                . 'search bar you will use on every screen.'),
            'groups' => [
                [
                    'id' => 'orientation',
                    'title' => __('Orientation'),
                    'steps' => [
                        [
                            'title' => __('Welcome to MISP'),
                            'body' => '<p>' . __('MISP is where your team '
                                . 'stores and shares threat intelligence. '
                                . 'This short tour points at the real '
                                . 'interface as you go.') . '</p><p>'
                                . __('It only covers the parts your account '
                                . 'has access to. Use <strong>Next</strong> '
                                . 'to move on, or leave at any time — every '
                                . 'step has a skip control.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-datapoints"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'title' => __('Data points'),
                            'body' => '<p>' . __('Events, attributes and '
                                . 'objects. An <strong>event</strong> is a '
                                . 'container for one incident or report; the '
                                . '<strong>attributes</strong> inside it are '
                                . 'the individual indicators.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-datamodels"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'title' => __('Data models'),
                            'body' => '<p>' . __('The vocabularies you '
                                . 'classify events with: taxonomies, '
                                . 'galaxies, warning lists and templates.')
                                . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-sync"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['servers', 'index'],
                            'title' => __('Sync'),
                            'body' => '<p>' . __('Connections to other MISP '
                                . 'instances and to external feeds. This is '
                                . 'how intelligence arrives without anyone '
                                . 'typing it in.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-administration"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['users', 'admin_index'],
                            'title' => __('Administration'),
                            'body' => '<p>' . __('Users, organisations, roles '
                                . 'and instance settings. Only shown to '
                                . 'accounts that administer the '
                                . 'instance.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-logs"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['logs', 'index'],
                            'title' => __('Logs'),
                            'body' => '<p>' . __('Who did what, and when. '
                                . 'Application logs cover activity, audit '
                                . 'logs record every change to the data, and '
                                . 'access logs track requests.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-api"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['events', 'automation'],
                            'title' => __('API and automation'),
                            'body' => '<p>' . __('Everything the interface '
                                . 'does is available over the REST API. The '
                                . 'built-in client lets you build and try a '
                                . 'query without leaving MISP, and the export '
                                . 'formats live here too.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-resources"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Resources'),
                            'body' => '<p>' . __('The user guide, the '
                                . 'reference for categories and attribute '
                                . 'types, and the theme switcher. Worth a '
                                . 'bookmark while the vocabulary is still '
                                . 'new.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-bookmarks"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Bookmarks'),
                            'body' => '<p>' . __('Pin the searches and pages '
                                . 'you come back to. They stay in reach from '
                                . 'any screen.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-account"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'title' => __('Your account'),
                            'body' => '<p>' . __('Your profile, dark mode, and '
                                . '<strong>Replay the tutorial</strong> — this '
                                . 'tour is always one click away from '
                                . 'here.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('The page header'),
                            'body' => '<p>' . __('Every screen opens with the '
                                . 'same header: where you are, how many '
                                . 'records matched, and the actions available '
                                . 'on them.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="page-actions"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Page actions'),
                            'body' => '<p>' . __('The buttons that act on what '
                                . 'you are looking at. They change from screen '
                                . 'to screen, but always sit here.') . '</p>',
                        ],
                        // The index toolbar, control by control. Every list
                        // in MISP is built from this same scaffold, so what
                        // is learned here applies everywhere.
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="index-search"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Search'),
                            'body' => '<p>' . __('Free-text search across the '
                                . 'list. It is on every index in MISP, and '
                                . 'the term is kept in the URL — a search can '
                                . 'be bookmarked or sent to a colleague as a '
                                . 'link.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="index-filters"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Filters'),
                            'body' => '<p>' . __('Narrow the list by the '
                                . 'fields that matter for it — distribution, '
                                . 'threat level, organisation. Filters stack '
                                . 'with the search rather than replacing '
                                . 'it.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="index-pagination"]',
                            'placement' => 'top',
                            'optional' => true,
                            'title' => __('Pagination'),
                            'body' => '<p>' . __('How many records matched and '
                                . 'where you are in them. The same controls '
                                . 'sit at the top of the list, so you never '
                                . 'have to scroll back up to turn a '
                                . 'page.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '[data-tour="index-view"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Table or cards'),
                            'body' => '<p>' . __('The same data, two '
                                . 'densities: a table for scanning many rows '
                                . 'at once, cards for reading fewer in more '
                                . 'detail. Your choice is remembered.')
                                . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            'anchor' => '.table-scroll tbody tr',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('A row'),
                            'body' => '<p>' . __('One record per row, with its '
                                . 'key fields as columns. Sort by any column '
                                . 'from its header, and double-click a row to '
                                . 'open it.') . '</p>',
                        ],
                        [
                            'page' => '/events/index',
                            // Overmind indexes render row actions as a
                            // row_actions field, not the core actions
                            // element — hence idx-col-*, not
                            // .action-links.
                            'anchor' => 'td.idx-col-row_actions',
                            'placement' => 'left',
                            'optional' => true,
                            'title' => __('The actions column'),
                            'body' => '<p>' . __('The last column holds what '
                                . 'you can do to that record — view, edit, '
                                . 'delete — and only shows the actions your '
                                . 'permissions allow, so it is shorter for '
                                . 'some accounts than others.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'account',
                    'title' => __('Your account and API access'),
                    'steps' => self::accountSteps(),
                ],
            ],
        ];
    }

    private static function accountSteps()
    {
        return [
            [
                'page' => '/users/view/me',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'title' => __('Your profile'),
                'body' => '<p>' . __('Your organisation and your role. The '
                    . 'role decides which buttons you get everywhere else — if '
                    . 'one you expect is missing, this is where to look.')
                    . '</p>',
            ],
            [
                'page' => '/users/view/me',
                'anchor' => '[data-tour="action-edit-profile"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Password, PGP key, notifications'),
                'body' => '<p>' . __('Change your password, add a PGP key so '
                    . 'MISP can email you encrypted, and choose what you are '
                    . 'notified about: each published event, or a daily, weekly '
                    . 'or monthly digest.') . '</p>',
            ],
            [
                'page' => '/users/view/me',
                'anchor' => '[data-tour="view-tab-settings"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Personal settings'),
                'body' => '<p>' . __('Your home page, the columns hidden from '
                    . 'your event list, the filters behind your digest and the '
                    . 'defaults applied to your API searches.') . '</p>',
            ],
            [
                'page' => '/users/view/me',
                'anchor' => '[data-tour="view-tab-authkeys"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['auth_keys', 'index'],
                'title' => __('Auth keys'),
                'body' => '<p>' . __('Scripts and tools such as PyMISP sign in '
                    . 'with an auth key, never with your password. Create one '
                    . 'per tool and give it an expiry: revoking one leaves the '
                    . 'others working.') . '</p>',
            ],
            [
                'page' => '/api/rest',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['api', 'rest'],
                'title' => __('Try the API'),
                'body' => '<p>' . __('The REST client sends a query to any '
                    . 'endpoint and shows the answer. Most integrations start '
                    . 'from <code>/attributes/restSearch</code>: filter by type, '
                    . 'tag, date or IDS flag, and pick the output format.')
                    . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 2. Find and read intelligence — everyone                            */
    /* ------------------------------------------------------------------ */

    private static function investigate()
    {
        return [
            'id' => 'investigate',
            'title' => __('Find and read intelligence'),
            'icon' => 'fas fa-magnifying-glass',
            'colour' => 'correlation',
            'summary' => __('Look an indicator up, read an event and follow '
                . 'what it connects to.'),
            'requires' => ['events', 'index'],
            'groups' => [
                [
                    'id' => 'lookup',
                    'title' => __('Look up an indicator'),
                    'requires' => ['attributes', 'index'],
                    'steps' => self::lookupSteps(),
                ],
                [
                    'id' => 'read',
                    'title' => __('Read an event'),
                    'steps' => self::readSteps(),
                ],
                [
                    'id' => 'respond',
                    'title' => __('Respond to it'),
                    'steps' => self::respondSteps(),
                ],
            ],
        ];
    }

    private static function lookupSteps()
    {
        return [
            [
                'page' => '/attributes/index',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'title' => __('Has anyone seen this?'),
                'body' => '<p>' . __('The attribute index lists every '
                    . 'indicator, from every event you are allowed to see. It '
                    . 'is the first place to check an IP address, a domain or a '
                    . 'hash you have just come across.') . '</p>',
            ],
            [
                'page' => '/attributes/index',
                'anchor' => '[data-tour="index-search"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Search by value'),
                'body' => '<p>' . __('This box takes a value, a UUID or a '
                    . 'comment. A hit means someone recorded it before you; no '
                    . 'hit is not proof that it is harmless.') . '</p>',
            ],
            [
                'page' => '/attributes/index',
                'anchor' => '[data-tour="index-filters"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Narrow it down'),
                'body' => '<p>' . __('Filter by type, category, creator '
                    . 'organisation, tag, galaxy or IDS flag — or keep only the '
                    . 'values that match a warning list.') . '</p>',
            ],
            [
                'page' => '/attributes/index',
                'anchor' => 'td.idx-col-id',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Back to the context'),
                'body' => '<p>' . __('A value alone says little. This column '
                    . 'links to the event it was reported in: the story, the '
                    . 'tags and the indicators that came with it.') . '</p>',
            ],
            [
                'page' => '/attributes/index',
                'anchor' => 'td.idx-col-ids',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Actionable or context'),
                'body' => '<p>' . __('The shield is the IDS flag: lit when the '
                    . 'author considers the value safe to alert or block on, '
                    . 'dim when it is context only. Rule exports for Suricata '
                    . 'or Snort only take flagged values.') . '</p>',
            ],
        ];
    }

    private static function readSteps()
    {
        return [
            self::openEventStep('/events/index', __('Open any event'),
                __('Pick any event in the list — the steps that follow work on '
                . 'whichever one you open.')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="ownership"]',
                'placement' => 'bottom',
                'waitingText' => __('Open an event to carry on reading.'),
                'title' => __('Who wrote it, who sees it'),
                'body' => '<p>' . __('The organisation that created the event, '
                    . 'the one holding this copy, and how far it is shared. '
                    . 'When part of its content is shared more narrowly than the '
                    . 'event itself, that is counted here too.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="event-general"]',
                'placement' => 'right',
                'optional' => true,
                'title' => __('At a glance'),
                'body' => '<p>' . __('Analysis and threat level as the author '
                    . 'set them, whether it is published, the period it covers '
                    . 'and what it is made of.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#related-card',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Related events'),
                'body' => '<p>' . __('Other events sharing at least one value '
                    . 'with this one — often the quickest way from a single '
                    . 'incident to the campaign behind it.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#warninglist-card',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Likely false positives'),
                'body' => '<p>' . __('Values that match a warning list: a '
                    . 'public resolver, a popular domain, a private address '
                    . 'range. Double-check these before blocking '
                    . 'anything.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-correlation"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Correlation'),
                'body' => '<p>' . __('The same links as a graph and a '
                    . 'timeline: this event, the values it shares and the '
                    . 'events at the other end.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-pivot-explorer"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Pivot Explorer'),
                'body' => '<p>' . __('The event&rsquo;s own content as a '
                    . 'graph — objects, attributes and the relationships between '
                    . 'them — to follow how one indicator leads to the '
                    . 'next.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-history"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('History'),
                'body' => '<p>' . __('Every change made to the event: what, '
                    . 'by whom and when.') . '</p>',
            ],
        ];
    }

    private static function respondSteps()
    {
        return [
            self::openEventStep('/events/index', __('Open any event'),
                __('Feedback is given on an event, so open one first.')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#sightings-card',
                'placement' => 'left',
                'waitingText' => __('Open an event to carry on.'),
                'title' => __('Sightings'),
                'body' => '<p>' . __('A sighting says <em>we saw this too</em> '
                    . '— or <em>this was a false positive</em>. It costs a '
                    . 'click, and it tells the author and every recipient that '
                    . 'the data is being used.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#analyst-data-card',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Notes and opinions'),
                'body' => '<p>' . __('Comment without editing: a '
                    . '<strong>note</strong> adds context, an '
                    . '<strong>opinion</strong> scores how far you agree. Both '
                    . 'can be attached to the event or to a single '
                    . 'attribute.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-download"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Take it with you'),
                'body' => '<p>' . __('Download the event as MISP JSON, CSV, '
                    . 'STIX, or as Suricata and Snort rules. To fetch the same '
                    . 'data on a schedule, use the API — see <strong>Your '
                    . 'account and API access</strong>.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-attributes"]',
                'placement' => 'bottom',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Value by value'),
                'body' => '<p>' . __('Open the <strong>Attributes</strong> tab: '
                    . 'sightings and corrections are given per value.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-sightings',
                'placement' => 'left',
                'optional' => true,
                'requires' => ['sightings', 'add'],
                'title' => __('Seen it?'),
                'body' => '<p>' . __('<strong>+</strong> records that you saw '
                    . 'the value, <strong>&minus;</strong> that it was a false '
                    . 'positive for you. The counters add up everyone&rsquo;s '
                    . 'sightings.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-row_actions',
                'placement' => 'left',
                'optional' => true,
                'requires' => ['shadowAttributes', 'edit'],
                'title' => __('Disagree? Propose a change'),
                'body' => '<p>' . __('On an event your organisation did not '
                    . 'create, the row menu offers <strong>Propose '
                    . 'change</strong>: the creator reviews it and decides. '
                    . 'Their data is never edited behind their back.') . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 3. Report an incident — needs the right to create events            */
    /* ------------------------------------------------------------------ */

    private static function reportIncident()
    {
        return [
            'id' => 'report-incident',
            'title' => __('Report an incident'),
            'icon' => 'fas fa-file-circle-plus',
            'colour' => 'tag',
            'summary' => __('The end-to-end path: open an event, fill it, '
                . 'classify it, then share it.'),
            'requires' => ['events', 'add'],
            'groups' => [
                [
                    'id' => 'create',
                    'title' => __('Create the event and feed it'),
                    'steps' => self::createSteps(),
                ],
                [
                    'id' => 'classify',
                    'title' => __('Classify it'),
                    'steps' => self::classifySteps(),
                ],
                [
                    'id' => 'share',
                    'title' => __('Share and publish it'),
                    'steps' => self::shareSteps(),
                ],
            ],
        ];
    }

    private static function createSteps()
    {
        return [
            [
                'page' => '/events/index',
                'anchor' => '#add-event-button',
                'placement' => 'bottom',
                'advance' => 'click',
                'skipIf' => self::EVENT_VIEW_MATCH,
                'title' => __('Start a new event'),
                'body' => '<p>' . __('Go ahead and click <strong>Add '
                    . 'Event</strong>. The tour follows you into the '
                    . 'dialog.') . '</p>',
            ],
            [
                'anchor' => '#EventInfo',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Name the event'),
                'body' => '<p>' . __('One line describing what happened — this '
                    . 'is what your colleagues read first in the event list.')
                    . '</p><p>' . __('Be specific: &ldquo;Phishing campaign '
                    . 'impersonating ACME invoices&rdquo; beats '
                    . '&ldquo;phishing&rdquo;.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="event-distribution"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Who gets to see it'),
                'body' => '<p>' . __('Distribution decides how far the event '
                    . 'travels: your organisation only, this community, '
                    . 'connected communities, everyone, or a named sharing '
                    . 'group.') . '</p><p>' . __('It is the single most '
                    . 'important field on this form — it is what stops '
                    . 'sensitive data leaving your org.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="event-analysis"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Analysis level'),
                'body' => '<p>' . __('How far along your own investigation is. '
                    . 'Start at <strong>Initial</strong> and raise it as the '
                    . 'picture firms up — recipients use it to judge how much '
                    . 'to trust the event.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="event-threat"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Threat level'),
                'body' => '<p>' . __('How dangerous this is to the people '
                    . 'receiving it. It drives triage on the other side, so '
                    . 'keep it honest.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="event-date"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Event date'),
                'body' => '<p>' . __('The date the activity happened, not the '
                    . 'date you are typing this in. It defaults to today; type '
                    . 'it as DD/MM/YYYY or pick it from the calendar.') . '</p>',
            ],
            [
                'anchor' => '#EventSubmitButton',
                'placement' => 'top',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Create it'),
                'body' => '<p>' . __('Submit the form. MISP opens the new '
                    . 'event and the tour picks up there.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tabs"]',
                'placement' => 'bottom',
                'waitingText' => __('Create your event to carry on — the '
                    . 'tutorial resumes on the event page.'),
                'title' => __('Inside an event'),
                'body' => '<p>' . __('An event is empty until you feed it. '
                    . 'These tabs hold its attributes, objects, reports and '
                    . 'correlations — the counters tell you what is already '
                    . 'there.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="quick-actions"]',
                'placement' => 'left',
                'title' => __('Quick actions'),
                'body' => '<p>' . __('Everything you can do to this event in '
                    . 'one column: add data, populate it from a report, export '
                    . 'it, publish it.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-add-attribute"]',
                'placement' => 'left',
                'advance' => 'click',
                'optional' => true,
                'requires' => ['attributes', 'add'],
                'title' => __('Add your first attribute'),
                'body' => '<p>' . __('Click <strong>Add Attribute</strong> to '
                    . 'record a single indicator — a hash, a domain, an IP '
                    . 'address.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="attribute-category"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Category'),
                'body' => '<p>' . __('What role the indicator plays: network '
                    . 'activity, payload delivery, artefacts dropped, and so '
                    . 'on. The category narrows the types offered '
                    . 'next.') . '</p>',
            ],
            [
                'anchor' => '[data-tour="attribute-type"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Type'),
                'body' => '<p>' . __('The concrete kind of value — '
                    . '<code>md5</code>, <code>domain</code>, '
                    . '<code>ip-src</code>. Type is what lets MISP correlate '
                    . 'your indicator against everyone else&rsquo;s.')
                    . '</p>',
            ],
            [
                'anchor' => '[data-tour="attribute-value"]',
                'placement' => 'right',
                'optional' => true,
                'interactive' => true,
                'title' => __('Value'),
                'body' => '<p>' . __('The indicator itself. You can paste '
                    . 'several at once and tick batch import to create one '
                    . 'attribute per line.') . '</p>',
            ],
            [
                'anchor' => '#card-ids',
                'placement' => 'top',
                'optional' => true,
                'interactive' => true,
                'title' => __('Actionable or context?'),
                'body' => '<p>' . __('<strong>IDS</strong> marks an attribute '
                    . 'as safe to push into detection tools. Leave it off for '
                    . 'context that would generate false positives — a '
                    . 'legitimate domain an attacker abused, for '
                    . 'instance.') . '</p>',
            ],
            self::saveStep(__('Add the attribute')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-attributes"]',
                'placement' => 'bottom',
                'closeModal' => true,
                'optional' => true,
                'title' => __('Where it all lands'),
                'body' => '<p>' . __('Whatever you add shows up under '
                    . '<strong>Attributes</strong>, where you can filter, edit '
                    . 'and export it.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-populate-from"]',
                'placement' => 'left',
                'closeModal' => true,
                'optional' => true,
                'title' => __('The fast way to feed an event'),
                'body' => '<p>' . __('Typing indicators one at a time gets '
                    . 'old. <strong>Import from</strong> takes a whole '
                    . 'report, finds the indicators in it and proposes them in '
                    . 'bulk for you to accept.') . '</p>',
            ],
        ];
    }

    /**
     * Closes a walk through a dialog's form: the tour waits on the submit
     * button until the dialog is gone, whether the form was saved or
     * discarded, instead of closing it under the user.
     *
     * @param string $action What submitting does, e.g. "Add the attribute".
     * @return array
     */
    private static function saveStep($action)
    {
        return [
            'anchor' => '#mainModal [data-tour="modal-submit"]',
            'placement' => 'top',
            'advance' => 'modal',
            'optional' => true,
            'title' => __('Save it'),
            'body' => '<p>' . __('%s — or <strong>Discard</strong> to carry '
                . 'on without it. The tutorial picks up as soon as the dialog '
                . 'closes.', $action) . '</p>',
        ];
    }

    private static function classifySteps()
    {
        return [
            self::openEventStep('/events/index', __('Open any event'),
                __('Classification happens on an event, so pick one from the '
                . 'list — any will do.')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tags-card',
                'placement' => 'right',
                'waitingText' => __('Open an event to carry on with '
                    . 'classification.'),
                'title' => __('Tags'),
                'body' => '<p>' . __('Tags come from '
                    . '<strong>taxonomies</strong> — agreed vocabularies '
                    . 'rather than free text. <code>tlp:amber</code> means the '
                    . 'same thing to every MISP user, which is exactly why '
                    . 'tags are worth more than notes.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="event-tags-edit"]',
                // Above, so the "⋯" menu the button may be folded into can
                // drop open without the popover covering it.
                'placement' => 'top',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Apply a tag'),
                'body' => '<p>' . __('Click <strong>Edit Tags</strong> — on a '
                    . 'narrow card it sits behind the '
                    . '<strong>&hellip;</strong> menu. Start with a '
                    . '<code>tlp:</code> tag: it states how far the recipient '
                    . 'may pass the event on.') . '</p>',
            ],
            [
                'anchor' => '#mainModalBody',
                'placement' => 'left',
                'advance' => 'modal',
                'optional' => true,
                'title' => __('The tag picker'),
                'body' => '<p>' . __('Search across every enabled taxonomy, '
                    . 'select the tags to apply, then <strong>Save '
                    . 'Tags</strong> — or <strong>Discard</strong> to carry '
                    . 'on. Local tags stay on your instance and are never '
                    . 'shared onward.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#galaxy-card',
                'placement' => 'right',
                'closeModal' => true,
                'optional' => true,
                'title' => __('Galaxies'),
                'body' => '<p>' . __('Where tags label an event, galaxies '
                    . 'connect it to known things: threat actors, malware '
                    . 'families, ATT&amp;CK techniques.') . '</p><p>'
                    . __('Attach the right cluster and your event joins '
                    . 'everything else attributed to that actor.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="event-galaxies-edit"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Attach a cluster'),
                'body' => '<p>' . __('The picker searches every galaxy at '
                    . 'once. There are tens of thousands of clusters, so type '
                    . 'a name rather than browsing. Clusters can also be put '
                    . 'on a single attribute, from its row.') . '</p>',
            ],
        ];
    }

    private static function shareSteps()
    {
        return [
            self::openEventStep('/events/index', __('Open any event'),
                __('Sharing is decided per event, so open one to see the '
                . 'controls in place.')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="event-general"]',
                'placement' => 'right',
                'waitingText' => __('Open an event to carry on with sharing '
                    . 'and publication.'),
                'title' => __('Distribution, in place'),
                'body' => '<p>' . __('The event&rsquo;s distribution is shown '
                    . 'here, and each attribute carries its own. An attribute '
                    . 'is never shared more widely than the event that holds '
                    . 'it, so the event level is the ceiling.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-edit-event"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Changing it later'),
                'body' => '<p>' . __('<strong>Edit Event</strong> reopens the '
                    . 'creation form, distribution included. Narrowing it '
                    . 'afterwards does not recall the copies other instances '
                    . 'have already pulled.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="quick-actions"]',
                'placement' => 'left',
                'title' => __('Before you publish'),
                'body' => '<p>' . __('Publishing is not a save button. Check '
                    . 'the distribution and the tags first — an unpublished '
                    . 'event stays with your organisation.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                // Matches whichever of the two the event currently shows, so
                // the step lands on published events too.
                'anchor' => '[data-tour="action-publish"],'
                    . ' [data-tour="action-unpublish"]',
                'placement' => 'left',
                'optional' => true,
                'requires' => ['events', 'publish'],
                'title' => __('Publish'),
                'body' => '<p>' . __('Publishing marks the event as ready and '
                    . 'hands it to everyone its distribution allows — '
                    . 'connected instances pull it, and subscribers may be '
                    . 'emailed.') . '</p><p>' . __('You can unpublish '
                    . 'afterwards, but you cannot recall what has already been '
                    . 'pulled. Treat it as a one-way door.') . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 4. Build out an event — same right, past the first attribute        */
    /* ------------------------------------------------------------------ */

    /**
     * @param string $ownEvents Event list filtered to the user's own
     *                          organisation, so a replayed group opens an
     *                          event whose edit controls are there.
     * @return array
     */
    private static function buildEvent($ownEvents)
    {
        return [
            'id' => 'build-event',
            'title' => __('Build out an event'),
            'icon' => 'fas fa-cubes',
            'colour' => 'tag',
            'onDemand' => true,
            'summary' => __('Objects, bulk imports, reports and attachments, '
                . 'and fine-tuning what is already there.'),
            'requires' => ['events', 'add'],
            'groups' => [
                [
                    'id' => 'objects',
                    'title' => __('Structure it with objects'),
                    'requires' => ['objects', 'add'],
                    'steps' => self::objectSteps($ownEvents),
                ],
                [
                    'id' => 'bulk',
                    'title' => __('Import in bulk'),
                    'requires' => ['events', 'populateFrom'],
                    'steps' => self::bulkSteps($ownEvents),
                ],
                [
                    'id' => 'context',
                    'title' => __('Report, attachment, enrichment'),
                    'steps' => self::contextSteps($ownEvents),
                ],
                [
                    'id' => 'refine',
                    'title' => __('Fine-tune attributes'),
                    'steps' => self::refineSteps($ownEvents),
                ],
            ],
        ];
    }

    private static function openOwnEventStep($ownEvents)
    {
        return self::openEventStep($ownEvents,
            __('Open one of your events'),
            __('The list is filtered to your organisation&rsquo;s events — the '
            . 'ones you can edit. Create one first in <strong>Report an '
            . 'incident</strong> if it is empty.'));
    }

    private static function objectSteps($ownEvents)
    {
        return [
            self::openOwnEventStep($ownEvents),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-add-object"]',
                'placement' => 'left',
                'advance' => 'click',
                'closeModal' => true,
                'optional' => true,
                'waitingText' => __('Open one of your organisation&rsquo;s '
                    . 'events to carry on.'),
                'title' => __('Add an object'),
                'body' => '<p>' . __('An object groups the attributes that '
                    . 'describe one thing: a file and its hashes, a domain and '
                    . 'the addresses it resolves to, an email and its headers. '
                    . 'Click <strong>Add Object</strong>.') . '</p>',
            ],
            [
                // The whole picker, popover above: the list opens downwards.
                'anchor' => '#objectTemplatePicker',
                'placement' => 'top',
                'optional' => true,
                'interactive' => true,
                'title' => __('Pick a template'),
                'body' => '<p>' . __('A template decides what the object '
                    . 'holds. Search it by name — <code>domain-ip</code>, '
                    . '<code>file</code>, <code>email</code> — or narrow the '
                    . 'list by category first.') . '</p>',
            ],
            [
                'anchor' => '#objNextBtn',
                'placement' => 'top',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Open its form'),
                'body' => '<p>' . __('Once a template is picked, '
                    . '<strong>Next</strong> opens the form built from '
                    . 'it.') . '</p>',
            ],
            [
                'anchor' => '#objectAddForm #editTable',
                'placement' => 'top',
                'optional' => true,
                'interactive' => '#objectAddForm',
                'title' => __('Its attributes'),
                'body' => '<p>' . __('What the template requires is already '
                    . 'laid out as rows. Everything else waits as a chip — '
                    . 'click one, <strong>+ Domain</strong> for instance, to '
                    . 'add it as a row and fill it in.') . '</p>',
            ],
            [
                'anchor' => '#objectAddForm .ov-obj-toggle-ids',
                'placement' => 'left',
                'optional' => true,
                'interactive' => '#objectAddForm',
                'title' => __('IDS and correlation, per value'),
                'body' => '<p>' . __('Each row has its own switches. Turn '
                    . '<strong>IDS</strong> off for context that should never '
                    . 'raise an alert, and <strong>correlation</strong> off for '
                    . 'a value that would match everything — a shared hosting '
                    . 'address, a common file name.') . '</p>',
            ],
            [
                'anchor' => '#objRelationshipBtn',
                'placement' => 'top',
                'optional' => true,
                'interactive' => '#objectAddForm',
                'title' => __('Relate it'),
                'body' => '<p>' . __('Link the object to another one in the '
                    . 'event: <em>this file was dropped by that email</em>. '
                    . 'Relationships can also be drawn later, in the '
                    . '<strong>Pivot Explorer</strong>.') . '</p>',
            ],
            self::saveStep(__('Add the object')),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-objects"]',
                'placement' => 'bottom',
                'closeModal' => true,
                'optional' => true,
                'title' => __('Where objects live'),
                'body' => '<p>' . __('Saved objects are listed under '
                    . '<strong>Objects</strong>, each folding open on its '
                    . 'attributes. Its <strong>Edit</strong> button is where '
                    . 'you change its comment or its relationships '
                    . 'later.') . '</p>',
            ],
        ];
    }

    private static function bulkSteps($ownEvents)
    {
        return [
            self::openOwnEventStep($ownEvents),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-populate-from"]',
                'placement' => 'left',
                'advance' => 'click',
                'closeModal' => true,
                'optional' => true,
                'waitingText' => __('Open one of your organisation&rsquo;s '
                    . 'events to carry on.'),
                'title' => __('Import from'),
                'body' => '<p>' . __('When the indicators come in a report, a '
                    . 'mail or another MISP, do not retype them. Click '
                    . '<strong>Import from</strong>.') . '</p>',
            ],
            [
                'anchor' => '#headingpfFreetext',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Freetext import'),
                'body' => '<p>' . __('Paste any text — a blog post, an email, '
                    . 'a list. MISP picks out the addresses, domains, hashes '
                    . 'and URLs and shows them for review: you set the type, '
                    . 'category and IDS flag of each before anything is '
                    . 'saved.') . '</p>',
            ],
            [
                'anchor' => '#headingpfJson',
                'placement' => 'left',
                'optional' => true,
                'title' => __('MISP JSON'),
                'body' => '<p>' . __('Paste an event exported from another '
                    . 'MISP, or written by a script: its attributes, objects '
                    . 'and tags are added to this event. Regenerate the UUIDs '
                    . 'if the same content may already exist here.') . '</p>',
            ],
            [
                'anchor' => '#headingpfForensic',
                'placement' => 'left',
                'optional' => true,
                'title' => __('And more'),
                'body' => '<p>' . __('Forensic timelines, then one entry per '
                    . 'import module your administrator enabled — CSV, '
                    . 'OpenIOC, email files and others.') . '</p>',
            ],
            [
                'anchor' => '#populateFromAccordion',
                'placement' => 'left',
                'advance' => 'modal',
                'optional' => true,
                'title' => __('Try one'),
                'body' => '<p>' . __('Open a method, fill it in and submit it — '
                    . 'or close the dialog to carry on. Freetext opens its '
                    . 'review list in this same dialog; the tutorial waits '
                    . 'until you are done.') . '</p>',
            ],
        ];
    }

    private static function contextSteps($ownEvents)
    {
        return [
            self::openOwnEventStep($ownEvents),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-add-report"]',
                'placement' => 'left',
                'advance' => 'click',
                'closeModal' => true,
                'optional' => true,
                'requires' => ['eventReports', 'add'],
                'waitingText' => __('Open one of your organisation&rsquo;s '
                    . 'events to carry on.'),
                'title' => __('Write a report'),
                'body' => '<p>' . __('Indicators say <em>what</em>; a report '
                    . 'says <em>what happened</em>. Click <strong>Add Event '
                    . 'Report</strong>.') . '</p>',
            ],
            [
                'anchor' => '#EventReportName',
                'placement' => 'bottom',
                'optional' => true,
                'interactive' => 'form',
                'requires' => ['eventReports', 'add'],
                'title' => __('Name it'),
                'body' => '<p>' . __('The title colleagues will see in the '
                    . 'event&rsquo;s list of reports. It is required.') . '</p>',
            ],
            [
                'anchor' => '#EventReportContent',
                'placement' => 'left',
                'optional' => true,
                'interactive' => 'form',
                'requires' => ['eventReports', 'add'],
                'title' => __('Markdown, with MISP inside'),
                'body' => '<p>' . __('Reports are written in Markdown. '
                    . '<code>@[attribute](uuid)</code> or '
                    . '<code>@[object](uuid)</code> turn into links to the '
                    . 'event&rsquo;s own data; once the report is saved, its '
                    . 'editor completes them with '
                    . '<kbd>Ctrl</kbd>+<kbd>Space</kbd>.') . '</p>',
            ],
            self::saveStep(__('Add the report')) + [
                'requires' => ['eventReports', 'add'],
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-add-attachment"]',
                'placement' => 'left',
                'advance' => 'click',
                'closeModal' => true,
                'optional' => true,
                'requires' => ['attributes', 'add_attachment'],
                'title' => __('Attach a file'),
                'body' => '<p>' . __('A sample, a screenshot, the original '
                    . 'PDF. Click <strong>Add Attachment</strong>.') . '</p>',
            ],
            [
                'anchor' => '#card-malware',
                'placement' => 'top',
                'optional' => true,
                'interactive' => 'form',
                'requires' => ['attributes', 'add_attachment'],
                'title' => __('Malware or not'),
                'body' => '<p>' . __('Keep <strong>malware sample</strong> on '
                    . 'for anything malicious: MISP stores it in a '
                    . 'password-protected zip (<code>infected</code>) so nobody '
                    . 'opens it by accident. Turn it off for a harmless '
                    . 'document.') . '</p>',
            ],
            self::saveStep(__('Upload the file')) + [
                'requires' => ['attributes', 'add_attachment'],
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-enrich"]',
                'placement' => 'left',
                'closeModal' => true,
                'optional' => true,
                'requires' => ['events', 'enrichEvent'],
                'title' => __('Enrich'),
                'body' => '<p>' . __('Sends the event&rsquo;s values to the '
                    . 'enrichment modules enabled here — passive DNS, WHOIS, '
                    . 'reputation services — and adds what comes back. It runs '
                    . 'in the background; a single value can also be enriched '
                    . 'from its row menu.') . '</p>',
            ],
        ];
    }

    private static function refineSteps($ownEvents)
    {
        return [
            self::openOwnEventStep($ownEvents),
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-attributes"]',
                'placement' => 'bottom',
                'advance' => 'click',
                'closeModal' => true,
                'optional' => true,
                'waitingText' => __('Open one of your organisation&rsquo;s '
                    . 'events to carry on.'),
                'title' => __('The attribute list'),
                'body' => '<p>' . __('Most corrections are made in place, from '
                    . 'the list. Open the <strong>Attributes</strong> '
                    . 'tab.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-ids',
                'placement' => 'left',
                'optional' => true,
                'title' => __('IDS, in place'),
                'body' => '<p>' . __('Click the shield to switch the IDS flag '
                    . 'without opening the form — when a value turns out to be '
                    . 'a false positive, for instance.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-correlate',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Correlation, in place'),
                'body' => '<p>' . __('Turn correlation off for a value that '
                    . 'ties this event to everything else — a sandbox address, '
                    . 'a common user agent.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-tag_list',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Tags and clusters on one value'),
                'body' => '<p>' . __('Tags and galaxy clusters can sit on a '
                    . 'single attribute, not only on the event. The '
                    . '<strong>+</strong> in this column and the next opens the '
                    . 'same pickers.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#tab-attributes td.idx-col-row_actions',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Everything else'),
                'body' => '<p>' . __('Edit the value, comment or distribution '
                    . 'from the row menu. To change many at once, tick their '
                    . 'boxes: a toolbar appears for mass editing, tagging, or '
                    . 'grouping them into an object.') . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 5. Data models                                                      */
    /* ------------------------------------------------------------------ */

    /**
     * "Open one" on an index: the user clicks a row, and the steps after it
     * (built with onPage()) describe the record they landed on.
     *
     * @param string $page Index the step lives on, or null when it is
     *                     already on screen (a tab of a detail page).
     * @param string $link Fragment of the record URL, e.g. "/galaxies/view/".
     * @param string $body
     * @param string $scope Selector narrowing which index to look in.
     * @return array
     */
    private static function openRowStep($page, $link, $body, $scope = '')
    {
        $step = [
            'anchor' => trim($scope . ' [data-tour="index-table"] a[href*="'
                . $link . '"]'),
            'placement' => 'right',
            'advance' => 'click',
            'optional' => true,
            'title' => __('Open one'),
            'body' => '<p>' . $body . '</p>',
        ];
        if ($page !== null) {
            $step['page'] = $page;
        }
        return $step;
    }

    /**
     * A step about the record an openRowStep() led to. Skipped, rather than
     * waited for, when the user is not on it: an empty index has no row to
     * open, and the tour must not park on a page nobody can reach.
     *
     * @param string $match Path regex of the record's view.
     * @param array $step
     * @return array
     */
    private static function onPage($match, array $step)
    {
        return $step + ['skipUnless' => $match];
    }

    private static function dataModels()
    {
        return [
            'id' => 'data-models',
            'title' => __('Data models'),
            'icon' => 'fas fa-layer-group',
            'colour' => 'galaxy',
            'summary' => __('The shared vocabularies — taxonomies, galaxies, '
                . 'templates — and the lists that keep noise out.'),
            'requires' => ['taxonomies', 'index'],
            'groups' => [
                [
                    'id' => 'taxonomies',
                    'title' => __('Tags and taxonomies'),
                    'steps' => self::taxonomySteps(),
                ],
                [
                    'id' => 'galaxies',
                    'title' => __('Galaxies and clusters'),
                    'requires' => ['galaxies', 'index'],
                    'steps' => self::galaxySteps(),
                ],
                [
                    'id' => 'templates',
                    'title' => __('Event and object templates'),
                    'steps' => self::templateSteps(),
                ],
                [
                    'id' => 'lists',
                    'title' => __('Filters and lists'),
                    'requires' => ['warninglists', 'index'],
                    'steps' => self::listSteps(),
                ],
            ],
        ];
    }

    private static function taxonomySteps()
    {
        return [
            [
                'anchor' => '[data-tour="nav-datamodels"]',
                'openMenu' => true,
                'placement' => 'bottom',
                'title' => __('Where vocabularies live'),
                'body' => '<p>' . __('Everything in this section sits under '
                    . '<strong>Data models</strong>. If a tag you want does '
                    . 'not exist, its taxonomy is probably just not enabled '
                    . 'yet.') . '</p>',
            ],
            [
                'page' => '/taxonomies/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'title' => __('Taxonomies'),
                'body' => '<p>' . __('A taxonomy is a published vocabulary — '
                    . 'TLP, PAP, the admiralty scale. Enabling one makes its '
                    . 'tags available across the instance.') . '</p><p>'
                    . __('Tagging from a taxonomy rather than inventing labels '
                    . 'is what makes events searchable across '
                    . 'organisations.') . '</p>',
            ],
            self::openRowStep('/taxonomies/index', '/taxonomies/view/',
                __('Click a taxonomy to see the tags it defines.')),
            self::onPage(self::TAXONOMY_VIEW, [
                'anchor' => '[data-tour="taxonomy-general"]',
                'placement' => 'right',
                'title' => __('The taxonomy'),
                'body' => '<p>' . __('Its version and description, then its '
                    . 'settings. <strong>Enabled</strong>: its tags can be '
                    . 'attached. <strong>Required</strong>: an event cannot be '
                    . 'published without one of them. '
                    . '<strong>Highlighted</strong>: its tags stand out from '
                    . 'the others. <strong>Exclusive</strong>: only one of its '
                    . 'tags at a time.') . '</p>',
            ]),
            self::onPage(self::TAXONOMY_VIEW, [
                'anchor' => '[data-taxonomy-tags]',
                'placement' => 'left',
                'title' => __('One tag per value'),
                'body' => '<p>' . __('Each value of the vocabulary has a '
                    . 'status. <strong>Enabled</strong>: the tag exists and can '
                    . 'be applied. <strong>Disabled</strong>: it exists but is '
                    . 'kept out of the pickers. <strong>Not created</strong>: '
                    . 'there is no tag yet — a tagger can create it from its '
                    . 'row.') . '</p>',
            ]),
            [
                'page' => '/tags/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'requires' => ['tags', 'index'],
                'title' => __('Tags'),
                'body' => '<p>' . __('Every tag available on this instance, '
                    . 'from a taxonomy or made here, with whether it is local '
                    . 'only, hidden or exportable.') . '</p>',
            ],
            [
                'page' => '/tags/index',
                'anchor' => '[data-tour="index-table"] .tag-star',
                'placement' => 'right',
                'optional' => true,
                'requires' => ['tags', 'index'],
                'title' => __('Favourites'),
                'body' => '<p>' . __('Star the tags you use most. The '
                    . '<strong>Favourite</strong> filter, under More filters, '
                    . 'then narrows the list down to them.') . '</p>',
            ],
            [
                'page' => '/tags/index',
                'anchor' => '[data-tour="page-actions"] a[href*="/tags/add"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['tags', 'add'],
                'title' => __('Your own tags'),
                'body' => '<p>' . __('When no taxonomy fits, create a tag: a '
                    . 'name and a colour. Prefer a taxonomy whenever one '
                    . 'exists — a home-made tag means nothing to other '
                    . 'organisations.') . '</p>',
            ],
            [
                'page' => '/tagCollections/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'optional' => true,
                'requires' => ['tagCollections', 'index'],
                'title' => __('Tag collections'),
                'body' => '<p>' . __('Tags that always travel together — a '
                    . 'TLP level, a sector, an actor — grouped under one name, '
                    . 'so they are attached in one go rather than one by '
                    . 'one.') . '</p>',
            ],
            [
                'page' => '/tagCollections/index',
                'anchor' => '[data-tour="page-actions"] '
                    . 'a[href*="/tagCollections/addWithTags"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['tagCollections', 'add'],
                'title' => __('Make a collection'),
                'body' => '<p>' . __('Pick the tags, name the set and choose '
                    . 'how far it is shared.') . '</p>',
            ],
        ];
    }

    private static function galaxySteps()
    {
        return [
            [
                'page' => '/galaxies/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'title' => __('Galaxies and clusters'),
                'body' => '<p>' . __('A galaxy is a catalogue of known things — '
                    . 'threat actors, malware, ATT&amp;CK techniques, sectors. '
                    . 'Each entry is a <strong>cluster</strong>.') . '</p><p>'
                    . __('Attaching a cluster to an event is how attribution '
                    . 'gets recorded in a way other instances '
                    . 'understand.') . '</p>',
            ],
            [
                'page' => '/galaxies/index',
                'anchor' => '[data-tour="page-actions"] '
                    . 'a[href*="/galaxies/add"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['galaxies', 'add'],
                'title' => __('A galaxy of your own'),
                'body' => '<p>' . __('Most galaxies come from the community '
                    . 'repository, but you can create one for knowledge of '
                    . 'your own — the actors your team tracks, the tools your '
                    . 'sector keeps meeting.') . '</p>',
            ],
            self::openRowStep('/galaxies/index', '/galaxies/view/',
                __('Click a galaxy to see what it holds.')),
            self::onPage(self::GALAXY_VIEW, [
                'anchor' => '[data-tour="galaxy-general"]',
                'placement' => 'right',
                'title' => __('The galaxy'),
                'body' => '<p>' . __('Its namespace, version and description, '
                    . 'and whether it is enabled: a disabled galaxy keeps its '
                    . 'clusters out of the pickers.') . '</p>',
            ]),
            self::onPage(self::GALAXY_VIEW, [
                'anchor' => '[data-tour="action-add-cluster"]',
                'placement' => 'left',
                'optional' => true,
                'requires' => ['galaxies', 'add'],
                'title' => __('Add a cluster'),
                'body' => '<p>' . __('A new entry in this galaxy — an actor or '
                    . 'a tool the catalogue does not know yet.') . '</p>',
            ]),
            self::onPage(self::GALAXY_VIEW, [
                'anchor' => '[data-tour="view-tab-clusters"]',
                'placement' => 'bottom',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Every cluster'),
                'body' => '<p>' . __('Open the <strong>Clusters</strong> '
                    . 'tab.') . '</p>',
            ]),
            self::onPage(self::GALAXY_VIEW, [
                'anchor' => '#tab-clusters [data-tour="index-table"]',
                'placement' => 'top',
                'optional' => true,
                'title' => __('The clusters'),
                'body' => '<p>' . __('One row per cluster, with its synonyms, '
                    . 'its creator and how many relations it has. The actions '
                    . 'column views, publishes or deletes one — or '
                    . '<strong>forks</strong> it: a copy of a community '
                    . 'cluster that you can adapt.') . '</p>',
            ]),
            self::onPage(self::GALAXY_VIEW, self::openRowStep(null,
                '/galaxy_clusters/view/',
                __('Click a cluster to see its details.'), '#tab-clusters')),
            self::onPage(self::CLUSTER_VIEW, [
                'anchor' => '[data-tour="cluster-general"]',
                'placement' => 'right',
                'title' => __('A cluster'),
                'body' => '<p>' . __('Its description, the tag that attaches '
                    . 'it — <code>misp-galaxy:…</code> — where it comes from '
                    . 'and whether it is published.') . '</p>',
            ]),
            self::onPage(self::CLUSTER_VIEW, [
                'anchor' => '[data-cluster-elements]',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Elements'),
                'body' => '<p>' . __('The structured details — aliases, '
                    . 'country, references, techniques — that make the cluster '
                    . 'searchable.') . '</p>',
            ]),
            self::onPage(self::CLUSTER_VIEW, [
                'anchor' => '[data-tour="view-tab-relations"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Relations'),
                'body' => '<p>' . __('How this cluster links to others: '
                    . '<em>uses</em>, <em>attributed-to</em>, '
                    . '<em>similar</em>… Following them is how you get from a '
                    . 'malware family to the actor behind it.') . '</p>',
            ]),
        ];
    }

    private static function templateSteps()
    {
        return [
            [
                'page' => '/event_templates/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'requires' => ['eventTemplates', 'index'],
                'title' => __('Event templates'),
                'body' => '<p>' . __('A ready-made form for a recurring kind '
                    . 'of report — a ransomware incident, a phishing wave. It '
                    . 'decides what the reporter is asked for, so every event '
                    . 'of that kind comes out the same shape.') . '</p>',
            ],
            self::openRowStep('/event_templates/index',
                '/event_templates/view/',
                __('Click a template to see how it is built.')) + [
                'requires' => ['eventTemplates', 'index'],
            ],
            self::onPage(self::EVENT_TEMPLATE_VIEW, [
                'anchor' => '[data-tour="event-template-general"]',
                'placement' => 'right',
                'title' => __('The template'),
                'body' => '<p>' . __('Whether it is active — offered when '
                    . 'someone creates an event — whether it comes from the '
                    . 'library or was made here, and what the reporter fills '
                    . 'in.') . '</p>',
            ]),
            self::onPage(self::EVENT_TEMPLATE_VIEW, [
                'anchor' => '[data-tour="event-template-defaults"]',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Event defaults'),
                'body' => '<p>' . __('The distribution, analysis and threat '
                    . 'level every event made from it starts with.') . '</p>',
            ]),
            self::onPage(self::EVENT_TEMPLATE_VIEW, [
                'anchor' => '[data-tour="event-template-structure"]',
                'placement' => 'top',
                'optional' => true,
                'title' => __('Structure'),
                'body' => '<p>' . __('The form itself, section by section: '
                    . 'the attributes, objects, tags and galaxies it asks for, '
                    . 'which are mandatory and which can be repeated.')
                    . '</p>',
            ]),
            self::onPage(self::EVENT_TEMPLATE_VIEW, [
                'anchor' => '[data-tour="action-template-instantiate"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Use it'),
                'body' => '<p>' . __('<strong>Create event from '
                    . 'template</strong> walks you through the form and builds '
                    . 'the event from your answers.') . '</p>',
            ]),
            [
                'page' => '/objectTemplates/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'requires' => ['objectTemplates', 'index'],
                'title' => __('Object templates'),
                'body' => '<p>' . __('Where an event template shapes a whole '
                    . 'report, an object template shapes one thing in it — a '
                    . 'file, a domain and its addresses, an email. They come '
                    . 'from the community repository and are what '
                    . '<strong>Add Object</strong> offers.') . '</p>',
            ],
            self::openRowStep('/objectTemplates/index', '/objectTemplates/view/',
                __('Click a template to see what it is made of.')) + [
                'requires' => ['objectTemplates', 'index'],
            ],
            self::onPage(self::OBJECT_TEMPLATE_VIEW, [
                'anchor' => '[data-tour="object-template-general"]',
                'placement' => 'right',
                'title' => __('The template'),
                'body' => '<p>' . __('Its version and meta-category, and '
                    . 'whether it is active: only active templates are offered '
                    . 'when adding an object.') . '</p>',
            ]),
            self::onPage(self::OBJECT_TEMPLATE_VIEW, [
                'anchor' => '[data-template-elements]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Its attributes'),
                'body' => '<p>' . __('Every attribute the object can hold, '
                    . 'with its type and whether it is required — or one of a '
                    . 'set where at least one must be filled in.') . '</p>',
            ]),
        ];
    }

    private static function listSteps()
    {
        return [
            [
                'page' => '/warninglists/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'title' => __('Warning lists'),
                'body' => '<p>' . __('Lists of values that are almost '
                    . 'certainly not malicious — public DNS resolvers, '
                    . 'top-ranked domains, RFC1918 ranges.') . '</p><p>'
                    . __('MISP flags attributes that hit an enabled list '
                    . 'instead of blocking them, so you keep the data but see '
                    . 'the warning.') . '</p>',
            ],
            [
                'page' => '/noticelists/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'optional' => true,
                'requires' => ['noticelists', 'index'],
                'title' => __('Notice lists'),
                'body' => '<p>' . __('The advisory counterpart: they attach '
                    . 'guidance to matching data — legal or handling notes an '
                    . 'analyst should read before acting, such as data '
                    . 'protection rules on personal information.') . '</p>',
            ],
            [
                'page' => '/regexp/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'optional' => true,
                'requires' => ['regexp', 'index'],
                'title' => __('Import regexps'),
                'body' => '<p>' . __('Rules applied to values as they come '
                    . 'in: a match is rewritten — a user name taken out of a '
                    . 'file path — or the value is refused altogether.')
                    . '</p>',
            ],
            [
                'page' => '/correlation_exclusions/index',
                'anchor' => '[data-tour="index-table"]',
                'placement' => 'top',
                'optional' => true,
                'requires' => ['correlationExclusions', 'index'],
                'title' => __('Correlation exclusions'),
                'body' => '<p>' . __('Values that never correlate — an '
                    . 'address every sandbox run touches, your own mail '
                    . 'server. They stay in their events but stop linking them '
                    . 'together.') . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 6. Investigate — values, profiles and graphs                        */
    /* ------------------------------------------------------------------ */

    private static function investigateValue()
    {
        return [
            'id' => 'investigate-value',
            'title' => __('Investigate a value'),
            'icon' => 'fas fa-magnifying-glass-chart',
            'colour' => 'correlation',
            'summary' => __('Everything known about one indicator, the profile '
                . 'that judges it, and the graphs that tie it to the rest.'),
            'groups' => [
                [
                    'id' => 'value-intelligence',
                    'title' => __('Value Intelligence'),
                    'requires' => ['values', 'index'],
                    'steps' => self::valueIntelligenceSteps(),
                ],
                [
                    'id' => 'analyst-profiles',
                    'title' => __('Analyst profiles'),
                    'requires' => ['analystProfiles', 'index'],
                    'steps' => self::analystProfileSteps(),
                ],
                [
                    'id' => 'pivot-explorer',
                    'title' => __('Pivot Explorer'),
                    'steps' => self::pivotExplorerSteps(),
                ],
                [
                    'id' => 'intelligence-graph',
                    'title' => __('Intelligence graph'),
                    'requires' => ['analystGraphs', 'view'],
                    'steps' => self::intelligenceGraphSteps(),
                ],
            ],
        ];
    }

    private static function valueIntelligenceSteps()
    {
        return [
            [
                'page' => '/values/index',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'skipIf' => self::VALUE_VIEW_MATCH,
                'title' => __('One value, everywhere'),
                'body' => '<p>' . __('An indicator rarely lives in a single '
                    . 'event. <strong>Value Intelligence</strong> gathers '
                    . 'every place a value appears — across events, '
                    . 'organisations and sightings — into one page.')
                    . '</p><p>' . __('It sits under <strong>Data '
                    . 'points</strong>.') . '</p>',
            ],
            [
                'page' => '/values/index',
                'anchor' => '#vi-prompt',
                'placement' => 'bottom',
                'skipIf' => self::VALUE_VIEW_MATCH,
                'title' => __('Look it up'),
                'body' => '<p>' . __('Paste an IP, a domain or a hash. '
                    . 'Defanged input is cleaned up for you.') . '</p><p>'
                    . __('Paste a list instead and you get one row per value '
                    . 'to triage, or switch to extraction to pull the values '
                    . 'out of a report.') . '</p>',
            ],
            [
                'page' => '/values/index',
                'anchor' => '[data-tour="values-run"]',
                'placement' => 'left',
                'advance' => 'click',
                'optional' => true,
                'skipIf' => self::VALUE_VIEW_MATCH,
                'title' => __('Open one'),
                'body' => '<p>' . __('Enter a value this instance holds and '
                    . 'press <strong>Open intelligence</strong>. The tour '
                    . 'picks up on its page.') . '</p>',
            ],
            [
                'pageMatch' => self::VALUE_VIEW_MATCH,
                'anchor' => '[data-tour="value-facts"]',
                'placement' => 'bottom',
                'waitingText' => __('Open a value to carry on. One nobody has '
                    . 'recorded yet stays on the lookup page with an '
                    . '<strong>Open anyway</strong> button.'),
                'title' => __('At a glance'),
                'body' => '<p>' . __('How often the value occurs, in how many '
                    . 'events, reported by how many organisations, and how '
                    . 'often it has been sighted.') . '</p>',
            ],
            [
                'pageMatch' => self::VALUE_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-assessment"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('The assessment'),
                'body' => '<p>' . __('MISP weighs what it holds about the '
                    . 'value and says which way it leans, and why.')
                    . '</p><p>' . __('What counts as evidence is decided by '
                    . 'your analyst profile — the next part.') . '</p>',
            ],
            [
                'pageMatch' => self::VALUE_VIEW_MATCH,
                'anchor' => '[data-tour="view-tabs"]',
                'placement' => 'bottom',
                'title' => __('Dig further'),
                'body' => '<p>' . __('Every occurrence, sightings over time, '
                    . 'related values, enrichment results and analyst notes '
                    . 'each have their own tab.') . '</p>',
            ],
        ];
    }

    private static function analystProfileSteps()
    {
        return [
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'title' => __('Analyst profiles'),
                'body' => '<p>' . __('A profile decides what MISP makes of a '
                    . 'value: which evidence counts and for how long, which '
                    . 'labels come first, and which enrichment modules may '
                    . 'run.') . '</p><p>' . __('One profile is in force for '
                    . 'you at a time. It scores every value page you open and '
                    . 'orders the context panel of an event.') . '</p>',
            ],
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="ap-resolution"]',
                'placement' => 'right',
                'title' => __('Which one applies'),
                'body' => '<p>' . __('MISP looks in three places in order — '
                    . 'your own choice, your organisation&rsquo;s, then the '
                    . 'instance default — and takes the first answer.')
                    . '</p>',
            ],
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="ap-profiles"]',
                'placement' => 'top',
                'title' => __('The profiles'),
                'body' => '<p>' . __('Every profile you can use, with its '
                    . 'standing: in force, overridden, not chosen or switched '
                    . 'off. Open one by its name to read what it '
                    . 'weighs.') . '</p>',
            ],
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="ap-row-actions"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Choosing one'),
                'body' => '<p>' . __('<strong>Use this</strong> makes a '
                    . 'profile yours; <strong>Stop using</strong> hands the '
                    . 'choice back to your organisation.') . '</p><p>'
                    . __('The menu beside it lets you try a profile on a real '
                    . 'value before committing to it.') . '</p>',
            ],
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="page-actions"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Making your own'),
                'body' => '<p>' . __('Fork an existing profile to get a copy '
                    . 'you can edit, or import one exported from another '
                    . 'instance.') . '</p><p>' . __('A shipped profile you '
                    . 'choose stays up to date; a fork stays as you left '
                    . 'it.') . '</p>',
            ],
            [
                'page' => '/analystProfiles/index',
                'anchor' => '[data-tour="ap-standing"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Where you stand'),
                'body' => '<p>' . __('The profile scoring you right now, what '
                    . 'this instance allows a profile to do, and the values '
                    . 'you pinned to check changes against.') . '</p>',
            ],
        ];
    }

    private static function pivotExplorerSteps()
    {
        return [
            [
                'page' => '/events/index',
                'anchor' => 'a[href*="/events/view"]',
                'placement' => 'right',
                'advance' => 'click',
                'optional' => true,
                'skipIf' => self::EVENT_VIEW_MATCH,
                'title' => __('Open any event'),
                'body' => '<p>' . __('The explorer starts from an event, so '
                    . 'pick one — ideally one with a few objects in '
                    . 'it.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="view-tab-pivot-explorer"]',
                'placement' => 'bottom',
                'advance' => 'click',
                'waitingText' => __('Open an event to carry on with the Pivot '
                    . 'Explorer.'),
                'title' => __('The event as a graph'),
                'body' => '<p>' . __('<strong>Pivot Explorer</strong> draws '
                    . 'the event as a graph: its objects, attributes and the '
                    . 'links between them. Open the tab to build it.')
                    . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="event-pivot-explorer"]',
                'placement' => 'top',
                'optional' => true,
                'title' => __('The canvas'),
                'body' => '<p>' . __('Each node is something in MISP, each '
                    . 'line a relationship — an object reference, a '
                    . 'correlation, a shared tag. Select a node to read its '
                    . 'details.') . '</p><p>' . __('Moving or hiding nodes '
                    . 'does not change the event. Double-click a node from '
                    . 'another event to open it.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#pivot-explorer-graph '
                    . '.pvt-moderail-button[data-mode="pivot"]',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Pivot from a node'),
                'body' => '<p>' . __('Pivot on a node to pull in what MISP '
                    . 'knows around it: correlations with other events, feed '
                    . 'hits, events sharing a tag, related clusters.')
                    . '</p><p>' . __('Right-clicking a node offers the same '
                    . 'menu. Large results are shown for review before they '
                    . 'land.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#pivot-explorer-graph .pvt-legend',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Legend and filters'),
                'body' => '<p>' . __('The legend names every colour: what a '
                    . 'node is, whether it belongs to this event or comes '
                    . 'from elsewhere, and what kind of link a line is. Click '
                    . 'an entry to filter the canvas.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '#pivot-explorer-graph '
                    . '.pvt-moderail-button[data-mode="create"]',
                'placement' => 'right',
                'optional' => true,
                'requires' => ['objectReferences', 'add'],
                'title' => __('Draw a relationship'),
                'body' => '<p>' . __('In <strong>Create</strong> mode, drag '
                    . 'from an object to another object or attribute and pick '
                    . 'the relationship — <code>drops</code>, '
                    . '<code>resolves-to</code>.') . '</p><p>' . __('Unlike '
                    . 'the rest of the canvas this edits the event: the '
                    . 'reference is saved straight away, and deleting a line '
                    . 'deletes it from MISP.') . '</p>',
            ],
        ];
    }

    private static function intelligenceGraphSteps()
    {
        return [
            [
                'anchor' => '[data-tour="nav-intel-graph"]',
                'placement' => 'bottom',
                'optional' => true,
                'requires' => ['analystGraphs', 'addNodes'],
                'title' => __('Your active graph'),
                'body' => '<p>' . __('Where the Pivot Explorer is for '
                    . 'exploring, an <strong>analyst graph</strong> keeps the '
                    . 'result: a saved, shareable drawing of how records '
                    . 'relate.') . '</p><p>' . __('This chip shows the graph '
                    . 'you are building. Every <strong>Add to graph</strong> '
                    . 'button in MISP sends its record here; click the chip to '
                    . 'open the graph beside any page.') . '</p>',
            ],
            [
                'page' => '/analystData/index/Graph',
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'skipIf' => self::GRAPH_VIEW_MATCH,
                'title' => __('All graphs'),
                'body' => '<p>' . __('Graphs are analyst data, attached to a '
                    . 'collection, an event or a galaxy cluster and shared '
                    . 'like any other record.') . '</p><p>' . __('Each one '
                    . 'also appears in a <strong>Graphs</strong> card on the '
                    . 'record it belongs to, which is where new ones are '
                    . 'started.') . '</p>',
            ],
            [
                'page' => '/analystData/index/Graph',
                'anchor' => '[data-tour="graph-row"]',
                'placement' => 'right',
                'optional' => true,
                'skipIf' => self::GRAPH_VIEW_MATCH,
                'title' => __('Open one'),
                'body' => '<p>' . __('Hover a thumbnail for a preview, then '
                    . 'double-click a row to open the graph.') . '</p>',
            ],
            [
                'pageMatch' => self::GRAPH_VIEW_MATCH,
                'anchor' => '[data-tour="graph-canvas"]',
                'placement' => 'top',
                'waitingText' => __('Open a graph from the list to carry on, '
                    . 'or skip this part if there are none yet.'),
                'title' => __('The canvas'),
                'body' => '<p>' . __('The same canvas as the Pivot Explorer, '
                    . 'but what you arrange here is kept: positions, nodes '
                    . 'pulled in from a pivot, nodes removed and links '
                    . 'hidden.') . '</p>',
            ],
            [
                'pageMatch' => self::GRAPH_VIEW_MATCH,
                'anchor' => '[data-tour="graph-bar"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Saving'),
                'body' => '<p>' . __('This bar says what has changed since the '
                    . 'last save. Only the organisation that owns a graph can '
                    . 'save it; if someone saved in the meantime, you are '
                    . 'offered to merge or reload.') . '</p>',
            ],
            [
                'pageMatch' => self::GRAPH_VIEW_MATCH,
                'anchor' => '[data-tour="page-actions"]',
                'placement' => 'bottom',
                'optional' => true,
                'title' => __('Settings and forks'),
                'body' => '<p>' . __('Rename a graph or change who can see it '
                    . 'from its settings.') . '</p><p>' . __('A graph from '
                    . 'another organisation is read-only: '
                    . '<strong>Fork</strong> it to get a copy your '
                    . 'organisation owns.') . '</p>',
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 7. Sync                                                             */
    /* ------------------------------------------------------------------ */

    private static function sync()
    {
        return [
            'id' => 'sync',
            'title' => __('Sync and feeds'),
            'icon' => 'fas fa-arrows-rotate',
            'colour' => 'report',
            'summary' => __('Where intelligence comes in from, where yours '
                . 'goes, and who you share it with.'),
            'requires' => ['servers', 'index'],
            'groups' => [
                [
                    'id' => 'servers',
                    'title' => __('Remote servers'),
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-sync"]',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'title' => __('Two ways data arrives'),
                            'body' => '<p>' . __('<strong>Servers</strong> are '
                                . 'two-way links to other MISP instances. '
                                . '<strong>Feeds</strong> pull from a URL or a '
                                . 'file. Both live under Sync.') . '</p>',
                        ],
                        [
                            'page' => '/servers/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Sync servers'),
                            'body' => '<p>' . __('Other MISP instances you '
                                . 'exchange with. Each link says whether you '
                                . 'pull from it, push to it, or both.')
                                . '</p><p>' . __('This list is the honest '
                                . 'answer to &ldquo;who receives what I '
                                . 'publish?&rdquo;.') . '</p>',
                        ],
                        [
                            'page' => '/servers/index',
                            'anchor' => '[data-tour="page-actions"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Before trusting a link'),
                            'body' => '<p>' . __('A new connection can be '
                                . 'tested before it carries anything — MISP '
                                . 'checks the credentials and reports what the '
                                . 'remote end would accept.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'feeds',
                    'title' => __('Feeds'),
                    'requires' => ['feeds', 'index'],
                    'steps' => [
                        [
                            'page' => '/feeds/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Feeds'),
                            'body' => '<p>' . __('One-way sources of '
                                . 'indicators, in MISP or CSV format. Enable '
                                . 'one and its data becomes searchable; cache '
                                . 'it and you can correlate against it without '
                                . 'importing everything.') . '</p>',
                        ],
                        [
                            'page' => '/feeds/index',
                            'anchor' => '[data-tour="page-actions"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Adding a source'),
                            'body' => '<p>' . __('Add a feed by URL, or import '
                                . 'a whole set of feed definitions at once. '
                                . 'The default list ships with MISP.')
                                . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'sharing-groups',
                    'title' => __('Sharing groups'),
                    'requires' => ['sharingGroups', 'index'],
                    'steps' => [
                        [
                            'page' => '/SharingGroups/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Sharing groups'),
                            'body' => '<p>' . __('When the fixed distribution '
                                . 'levels are too blunt, a sharing group names '
                                . 'exactly which organisations may see an '
                                . 'event.') . '</p><p>' . __('Pick '
                                . '&ldquo;Sharing group&rdquo; as an '
                                . 'event&rsquo;s distribution and this is the '
                                . 'list you choose from.') . '</p>',
                        ],
                        self::openRowStep('/SharingGroups/index',
                            '/SharingGroups/view/',
                            __('Click a sharing group to see who is in '
                            . 'it.')),
                        self::onPage(self::SHARING_GROUP_VIEW, [
                            'anchor' => '[data-tour="sharing-group-general"]',
                            'placement' => 'right',
                            'title' => __('The group'),
                            'body' => '<p>' . __('Whether it is offered as a '
                                . 'distribution, whether it may only travel '
                                . 'through the instances listed, and how many '
                                . 'events are shared with it.') . '</p>',
                        ]),
                        self::onPage(self::SHARING_GROUP_VIEW, [
                            'anchor' => '[data-tour="sharing-group-members"]',
                            'placement' => 'top',
                            'optional' => true,
                            'title' => __('Who is in it'),
                            'body' => '<p>' . __('The member organisations, '
                                . 'and the instances the group may travel '
                                . 'through. Data shared with the group reaches '
                                . 'them and no one else.') . '</p>',
                        ]),
                    ],
                ],
                [
                    'id' => 'integrations',
                    'title' => __('Other integrations'),
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-integrations"] '
                                . '> .dropdown-menu',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Integrations'),
                            'body' => '<p>' . __('Four more connections, '
                                . 'under <strong>Sync &rarr; '
                                . 'Integrations</strong>:') . '</p><ul>'
                                . '<li>' . __('<strong>Communities</strong> — '
                                . 'discover other MISP communities and ask to '
                                . 'join them.') . '</li>'
                                . '<li>' . __('<strong>Cerebrates</strong> — '
                                . 'pull organisations and sharing groups from '
                                . 'a Cerebrate directory.') . '</li>'
                                . '<li>' . __('<strong>TAXII servers</strong> '
                                . '— exchange STIX with tools outside '
                                . 'MISP.') . '</li>'
                                . '<li>' . __('<strong>Sighting DB</strong> — '
                                . 'look values up in a shared sightings '
                                . 'database.') . '</li></ul>',
                        ],
                    ],
                ],
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 8. Administration                                                   */
    /* ------------------------------------------------------------------ */

    private static function administration()
    {
        return [
            'id' => 'administration',
            'title' => __('Administration'),
            'icon' => 'fas fa-screwdriver-wrench',
            'colour' => 'category',
            'summary' => __('Instance settings, users, organisations and '
                . 'roles, and the automation behind them.'),
            'requires' => ['users', 'admin_index'],
            'groups' => [
                [
                    'id' => 'maintenance',
                    'title' => __('Instance settings'),
                    'requires' => ['servers', 'serverSettings'],
                    'steps' => self::settingsSteps(),
                ],
                [
                    'id' => 'users',
                    'title' => __('Users and organisations'),
                    'steps' => [
                        [
                            'page' => '/admin/users/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Users'),
                            'body' => '<p>' . __('Every account you '
                                . 'administer. A user belongs to one '
                                . 'organisation and carries one role, which '
                                . 'together decide what they can see and '
                                . 'do.') . '</p>',
                        ],
                        [
                            'page' => '/organisations/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'optional' => true,
                            'requires' => ['organisations', 'index'],
                            'title' => __('Organisations'),
                            'body' => '<p>' . __('Local organisations have '
                                . 'users on this instance; remote ones are '
                                . 'known only as the source of synced data. '
                                . 'Distribution rules are written in terms of '
                                . 'these.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'roles',
                    'title' => __('Roles and access'),
                    'requires' => ['roles', 'index'],
                    'steps' => [
                        [
                            'page' => '/roles/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Roles'),
                            'body' => '<p>' . __('A role is a named set of '
                                . 'permissions — publish, sync, tag, '
                                . 'administer. Changing a role changes what '
                                . 'every user holding it can do.') . '</p>'
                                . '<p>' . __('This tour respects them too: '
                                . 'sections your account cannot use are never '
                                . 'shown.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'workflows',
                    'title' => __('Workflows'),
                    'requires' => ['workflows', 'index'],
                    'steps' => [
                        [
                            'page' => '/workflows/index',
                            'anchor' => '[data-tour="index-table"]',
                            'placement' => 'top',
                            'title' => __('Workflows'),
                            'body' => '<p>' . __('Automation inside MISP. A '
                                . 'trigger — an event about to be published, '
                                . 'an attribute being saved — starts a chain '
                                . 'of modules that check conditions and act: '
                                . 'block the publication, enrich the data, '
                                . 'send a notification.') . '</p>',
                        ],
                        [
                            'page' => '/workflows/index',
                            'anchor' => '[data-tour="page-actions"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Before building one'),
                            'body' => '<p>' . __('<strong>How workflows '
                                . 'work</strong> explains triggers, modules '
                                . 'and blueprints — read it before editing a '
                                . 'trigger that can stop every '
                                . 'publication.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'admin-menu',
                    'title' => __('Blocklists and correlations'),
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-blocklisting"] '
                                . '> .dropdown-menu',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['eventBlocklists', 'index'],
                            'title' => __('Blocklists'),
                            'body' => '<p>' . __('Refuse an event, an '
                                . 'organisation or a sighting by its UUID: it '
                                . 'is never created, pulled or synced onto '
                                . 'this instance again, even if a partner '
                                . 'keeps sending it.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-correlations"] '
                                . '> .dropdown-menu',
                            'openMenu' => true,
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['correlations', 'top'],
                            'title' => __('Correlations'),
                            'body' => '<p>' . __('The values linking the most '
                                . 'events, the rules deciding what correlates, '
                                . 'and the <strong>over-correlating '
                                . 'values</strong> — so common that MISP stops '
                                . 'correlating them.') . '</p>',
                        ],
                    ],
                ],
            ],
        ];
    }

    private static function settingsSteps()
    {
        return [
            [
                'anchor' => '[data-tour="nav-administration"]',
                'openMenu' => true,
                'placement' => 'bottom',
                'title' => __('The admin menu'),
                'body' => '<p>' . __('Instance settings, accounts, '
                    . 'organisations and roles all hang off this menu. What '
                    . 'you see in it depends on whether you administer your '
                    . 'own organisation or the whole instance.') . '</p>',
            ],
            [
                'page' => '/servers/serverSettings',
                'pageMatch' => self::SETTINGS_PAGE,
                'anchor' => '[data-tour="page-title"]',
                'placement' => 'bottom',
                'title' => __('Server settings and diagnostics'),
                'body' => '<p>' . __('Every instance setting, grouped by area '
                    . 'in the menu on the left, next to the checks that say '
                    . 'whether the instance is healthy.') . '</p>',
            ],
            [
                'page' => '/servers/serverSettings',
                'pageMatch' => self::SETTINGS_PAGE,
                'anchor' => '[data-ss-search-open]',
                'placement' => 'right',
                'optional' => true,
                'title' => __('Find a setting'),
                'body' => '<p>' . __('Search every setting by name or '
                    . 'description, advanced and deprecated ones included — '
                    . 'faster than remembering which area it lives in. '
                    . '<kbd>Ctrl</kbd>+<kbd>K</kbd> opens it from anywhere on '
                    . 'the page.') . '</p>',
            ],
            [
                'page' => '/servers/serverSettings',
                'pageMatch' => self::SETTINGS_PAGE,
                'anchor' => '[data-tour="settings-attention"]',
                'placement' => 'left',
                'optional' => true,
                'title' => __('Needs attention'),
                'body' => '<p>' . __('Critical and recommended settings whose '
                    . 'current value fails its check, worst first. Click a '
                    . 'value to fix it right here.') . '</p>',
            ],
            [
                'page' => '/servers/serverSettings',
                'pageMatch' => self::SETTINGS_PAGE,
                'anchor' => '[data-tour="settings-health"]',
                'placement' => 'top',
                'optional' => true,
                'title' => __('System health'),
                'body' => '<p>' . __('Version, PHP, file permissions, the '
                    . 'database schema, the workers: one tile each, saying '
                    . 'whether that part of the instance is sound. Worth a look '
                    . 'after every upgrade.') . '</p>',
            ],
            [
                'page' => '/servers/serverSettings',
                'pageMatch' => self::SETTINGS_PAGE,
                'anchor' => '[data-tour="settings-essentials"]',
                'placement' => 'top',
                'optional' => true,
                'title' => __('Essentials'),
                'body' => '<p>' . __('The handful of settings every instance '
                    . 'has to get right, gathered in one place. Click a value '
                    . 'to change it.') . '</p>',
            ],
        ];
    }

    /**
     * Strings the JS engine renders itself. Kept here so the whole tour is
     * translated from one place.
     *
     * @return array
     */
    public static function uiStrings()
    {
        return [
            'next' => __('Next'),
            'back' => __('Back'),
            'finish' => __('Finish'),
            'nextSection' => __('Next section'),
            'nextPart' => __('Next part'),
            'skipPart' => __('Skip this part'),
            'skipSection' => __('Skip section'),
            'skipAll' => __('Skip tutorial'),
            'stepOf' => __('Step %1 of %2'),
            'stepCount' => __('%1 steps'),
            'partCount' => __('%1 parts'),
            'waitingForClick' => __('Waiting for you…'),
            'waitingDefault' => __('Carry on when you are ready — the '
                . 'tutorial picks up automatically.'),
            'tutorial' => __('Interactive tutorial'),
            'launcherTitle' => __('Choose where to start'),
            'sectionCount' => __('%1 sections'),
            'launcherHint' => __('Pick a section or a single part, or run the '
                . 'whole tour. Only what your account can use is listed.'),
            'onDemand' => __('On demand'),
            'onDemandHint' => __('Not part of the full tour: start it from '
                . 'here when you need it.'),
            'startSection' => __('Start this section'),
            'startAll' => __('Start the full tour'),
            'close' => __('Close'),
            'stopped' => __('Tutorial closed. Replay it from your account '
                . 'menu whenever you like.'),
            'finished' => __('Tutorial complete.'),
            'unavailable' => __('The tutorial could not be loaded.'),
        ];
    }
}
