<?php

/**
 * Step catalogue for the Overmind onboarding tour.
 *
 * Structure: the tour is cut along the navigation bar, so a section maps to
 * the part of MISP a given role actually works in. `general` is for everyone;
 * the other four mirror the first four navbar menus and are gated on the
 * permissions they need, which means a read-only analyst gets a short tour and
 * a site admin gets all of it. Each section is split into named groups
 * (sub-sections) that can be skipped or replayed on their own.
 *
 * Section keys
 *  - id, title, icon, summary
 *  - colour      Accent for the launcher card, named as an Overmind
 *                palette token (primary, tag, galaxy, …). onboarding.css
 *                maps the name to the token and carries the fallback, so
 *                no colour value is ever spelled out here.
 *  - requires    [controller, action] ACL gate for the whole section.
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
 *  - waitingText Copy for the dock while waiting on `pageMatch`.
 *  - advance     'button' (default) or 'click' to require the real click.
 *  - closeModal  Dismiss #mainModal before rendering; use when a step points
 *                back at the page behind a dialog the tour just opened.
 *  - optional    Skip silently when the anchor never materialises.
 *  - requires    [controller, action] gate evaluated against the user's ACL.
 */
class OnboardingTour
{
    /** Path fragment of any single event view, whichever route was used. */
    const EVENT_VIEW_MATCH = '^/events/(view2|view)/[0-9]+';

    /**
     * Build the catalogue, dropping anything the user cannot reach.
     *
     * Gates are ACL lookups rather than raw permission flags, which keeps this
     * honest with the rest of MISP and means a site admin passes every one of
     * them without needing a special case.
     *
     * @param callable $canAccess fn(string $controller, string $action): bool
     * @return array
     */
    public static function sections(callable $canAccess)
    {
        $sections = [
            self::general(),
            self::reportIncident(),
            self::dataModels(),
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
     * Close the tour on whichever section survived filtering last, so every
     * role gets a proper ending instead of stopping mid-topic.
     *
     * @param array $sections
     * @return array
     */
    private static function appendClosingStep(array $sections)
    {
        if (empty($sections)) {
            return $sections;
        }
        $lastIndex = count($sections) - 1;
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
                            'placement' => 'bottom',
                            'title' => __('Data models'),
                            'body' => '<p>' . __('The vocabularies you '
                                . 'classify events with: taxonomies, '
                                . 'galaxies, warning lists and templates.')
                                . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-sync"]',
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
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Bookmarks'),
                            'body' => '<p>' . __('Pin the searches and pages '
                                . 'you come back to. They stay in reach from '
                                . 'any screen.') . '</p>',
                        ],
                        [
                            'anchor' => '[data-tour="nav-account"]',
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
                            'anchor' => '.dropdown-filters',
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
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 2. Report an incident — needs the right to create events            */
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
                'title' => __('Threat level'),
                'body' => '<p>' . __('How dangerous this is to the people '
                    . 'receiving it. It drives triage on the other side, so '
                    . 'keep it honest.') . '</p>',
            ],
            // [
            //     'anchor' => '[data-tour="event-date"]',
            //     'placement' => 'right',
            //     'optional' => true,
            //     'title' => __('Event date'),
            //     'body' => '<p>' . __('The date the activity happened, not the '
            //         . 'date you are typing this in. It defaults to '
            //         . 'today.') . '</p>',
            // ],
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
                'title' => __('Value'),
                'body' => '<p>' . __('The indicator itself. You can paste '
                    . 'several at once and tick batch import to create one '
                    . 'attribute per line.') . '</p>',
            ],
            [
                'anchor' => '#card-ids',
                'placement' => 'top',
                'optional' => true,
                'title' => __('Actionable or context?'),
                'body' => '<p>' . __('<strong>IDS</strong> marks an attribute '
                    . 'as safe to push into detection tools. Leave it off for '
                    . 'context that would generate false positives — a '
                    . 'legitimate domain an attacker abused, for '
                    . 'instance.') . '</p>',
            ],
            [
                'pageMatch' => self::EVENT_VIEW_MATCH,
                'anchor' => '[data-tour="action-populate-from"]',
                'placement' => 'left',
                'closeModal' => true,
                'optional' => true,
                'title' => __('The fast way to feed an event'),
                'body' => '<p>' . __('Typing indicators one at a time gets '
                    . 'old. <strong>Populate from</strong> takes a whole '
                    . 'report, finds the indicators in it and proposes them in '
                    . 'bulk for you to accept.') . '</p>',
            ],
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
        ];
    }

    private static function classifySteps()
    {
        return [
            [
                'page' => '/events/index',
                'anchor' => 'a[href*="/events/view"]',
                'placement' => 'right',
                'advance' => 'click',
                'optional' => true,
                // Replayed on its own this opens an event first; reached from
                // the previous group the user is already sitting on one.
                'skipIf' => self::EVENT_VIEW_MATCH,
                'title' => __('Open any event'),
                'body' => '<p>' . __('Classification happens on an event, so '
                    . 'pick one from the list — any will do.') . '</p>',
            ],
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
                'placement' => 'left',
                'advance' => 'click',
                'optional' => true,
                'title' => __('Apply a tag'),
                'body' => '<p>' . __('Open the tag picker. Start with a '
                    . '<code>tlp:</code> tag — it states how far the recipient '
                    . 'may pass the event on.') . '</p>',
            ],
            [
                'anchor' => '#mainModalBody',
                'placement' => 'left',
                'optional' => true,
                'title' => __('The tag picker'),
                'body' => '<p>' . __('Search across every enabled taxonomy, '
                    . 'then select the tags to apply. Local tags stay on your '
                    . 'instance and are never shared onward.') . '</p>',
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
                    . 'a name rather than browsing.') . '</p>',
            ],
        ];
    }

    private static function shareSteps()
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
                'body' => '<p>' . __('Sharing is decided per event, so open '
                    . 'one to see the controls in place.') . '</p>',
            ],
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
    /* 3. Data models                                                      */
    /* ------------------------------------------------------------------ */

    private static function dataModels()
    {
        return [
            'id' => 'data-models',
            'title' => __('Data models'),
            'icon' => 'fas fa-layer-group',
            'colour' => 'galaxy',
            'summary' => __('The shared vocabularies: taxonomies, galaxies '
                . 'and the lists that keep noise out.'),
            'requires' => ['taxonomies', 'index'],
            'groups' => [
                [
                    'id' => 'taxonomies',
                    'title' => __('Tags and taxonomies'),
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-datamodels"]',
                            'placement' => 'bottom',
                            'title' => __('Where vocabularies live'),
                            'body' => '<p>' . __('Everything in this section '
                                . 'sits under <strong>Data models</strong>. '
                                . 'If a tag you want does not exist, its '
                                . 'taxonomy is probably just not enabled '
                                . 'yet.') . '</p>',
                        ],
                        [
                            'page' => '/taxonomies/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Taxonomies'),
                            'body' => '<p>' . __('A taxonomy is a published '
                                . 'vocabulary — TLP, PAP, the admiralty '
                                . 'scale. Enabling one makes its tags '
                                . 'available across the instance.') . '</p>'
                                . '<p>' . __('Tagging from a taxonomy rather '
                                . 'than inventing labels is what makes events '
                                . 'searchable across organisations.') . '</p>',
                        ],
                        [
                            'page' => '/taxonomies/index',
                            'anchor' => '[data-tour="index-search"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Finding one'),
                            'body' => '<p>' . __('There are well over a '
                                . 'hundred. Search by name, then open one to '
                                . 'enable it and pick which of its tags you '
                                . 'want exposed.') . '</p>',
                        ],
                        [
                            'page' => '/tags/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['tags', 'index'],
                            'title' => __('The resulting tags'),
                            'body' => '<p>' . __('Every tag available on this '
                                . 'instance, taxonomy-backed or custom, with '
                                . 'how often each one is used.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'galaxies',
                    'title' => __('Galaxies'),
                    'requires' => ['galaxies', 'index'],
                    'steps' => [
                        [
                            'page' => '/galaxies/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Galaxies and clusters'),
                            'body' => '<p>' . __('A galaxy is a catalogue of '
                                . 'known things — threat actors, malware, '
                                . 'ATT&amp;CK techniques, sectors. Each entry '
                                . 'is a <strong>cluster</strong>.') . '</p>'
                                . '<p>' . __('Attaching a cluster to an event '
                                . 'is how attribution gets recorded in a way '
                                . 'other instances understand.') . '</p>',
                        ],
                        [
                            'page' => '/galaxies/index',
                            'anchor' => '[data-tour="index-search"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'title' => __('Keeping them current'),
                            'body' => '<p>' . __('Galaxies ship from the '
                                . 'community repository and are updated in '
                                . 'place, so clusters stay in step with what '
                                . 'the rest of the ecosystem uses.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'lists',
                    'title' => __('Filters and lists'),
                    'requires' => ['warninglists', 'index'],
                    'steps' => [
                        [
                            'page' => '/warninglists/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Warning lists'),
                            'body' => '<p>' . __('Lists of values that are '
                                . 'almost certainly not malicious — public DNS '
                                . 'resolvers, top-ranked domains, RFC1918 '
                                . 'ranges.') . '</p><p>' . __('MISP flags '
                                . 'attributes that hit one instead of blocking '
                                . 'them, so you keep the data but see the '
                                . 'warning.') . '</p>',
                        ],
                        [
                            'page' => '/noticelists/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['noticelists', 'index'],
                            'title' => __('Notice lists'),
                            'body' => '<p>' . __('The advisory counterpart: '
                                . 'they attach guidance to matching data — '
                                . 'legal or handling notes an analyst should '
                                . 'read before acting.') . '</p>',
                        ],
                    ],
                ],
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 4. Sync                                                             */
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
                    'id' => 'feeds',
                    'title' => __('Feeds'),
                    'requires' => ['feeds', 'index'],
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-sync"]',
                            'placement' => 'bottom',
                            'title' => __('Two ways data arrives'),
                            'body' => '<p>' . __('<strong>Feeds</strong> pull '
                                . 'from a URL or a file. '
                                . '<strong>Servers</strong> are two-way links '
                                . 'to other MISP instances. Both live under '
                                . 'Sync.') . '</p>',
                        ],
                        [
                            'page' => '/feeds/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
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
                    'id' => 'servers',
                    'title' => __('Remote servers'),
                    'steps' => [
                        [
                            'page' => '/servers/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
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
                    'id' => 'sharing-groups',
                    'title' => __('Sharing groups'),
                    'requires' => ['sharingGroups', 'index'],
                    'steps' => [
                        [
                            'page' => '/SharingGroups/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Sharing groups'),
                            'body' => '<p>' . __('When the fixed distribution '
                                . 'levels are too blunt, a sharing group names '
                                . 'exactly which organisations may see an '
                                . 'event.') . '</p><p>' . __('Pick '
                                . '&ldquo;Sharing group&rdquo; as an '
                                . 'event&rsquo;s distribution and this is the '
                                . 'list you choose from.') . '</p>',
                        ],
                    ],
                ],
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* 5. Administration                                                   */
    /* ------------------------------------------------------------------ */

    private static function administration()
    {
        return [
            'id' => 'administration',
            'title' => __('Administration'),
            'icon' => 'fas fa-screwdriver-wrench',
            'colour' => 'category',
            'summary' => __('Users, organisations, roles and the instance '
                . 'settings behind them.'),
            'requires' => ['users', 'admin_index'],
            'groups' => [
                [
                    'id' => 'users',
                    'title' => __('Users and organisations'),
                    'steps' => [
                        [
                            'anchor' => '[data-tour="nav-administration"]',
                            'placement' => 'bottom',
                            'title' => __('The admin menu'),
                            'body' => '<p>' . __('Accounts, organisations, '
                                . 'roles and instance settings all hang off '
                                . 'this menu. What you see in it depends on '
                                . 'whether you administer your own '
                                . 'organisation or the whole '
                                . 'instance.') . '</p>',
                        ],
                        [
                            'page' => '/admin/users/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Users'),
                            'body' => '<p>' . __('Every account you '
                                . 'administer. A user belongs to one '
                                . 'organisation and carries one role, which '
                                . 'together decide what they can see and '
                                . 'do.') . '</p>',
                        ],
                        [
                            'page' => '/organisations/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
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
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Roles'),
                            'body' => '<p>' . __('A role is a named set of '
                                . 'permissions — publish, sync, tag, '
                                . 'administer. Changing a role changes what '
                                . 'every user holding it can do.') . '</p>'
                                . '<p>' . __('This tour respects them too: '
                                . 'sections your account cannot use are never '
                                . 'shown.') . '</p>',
                        ],
                        [
                            'page' => '/auth_keys/index',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'optional' => true,
                            'requires' => ['auth_keys', 'index'],
                            'title' => __('API keys'),
                            'body' => '<p>' . __('Automation authenticates '
                                . 'with these rather than a password. They '
                                . 'inherit their owner&rsquo;s permissions, so '
                                . 'issue them as narrowly as you '
                                . 'can.') . '</p>',
                        ],
                    ],
                ],
                [
                    'id' => 'maintenance',
                    'title' => __('Instance settings'),
                    'requires' => ['servers', 'serverSettings'],
                    'steps' => [
                        [
                            'page' => '/servers/serverSettings',
                            'anchor' => '[data-tour="page-title"]',
                            'placement' => 'bottom',
                            'title' => __('Server settings and diagnostics'),
                            'body' => '<p>' . __('Every instance setting, '
                                . 'grouped by area, with a diagnostics tab '
                                . 'that flags what is misconfigured.')
                                . '</p><p>' . __('Worth a look after any '
                                . 'upgrade: it reports on workers, the '
                                . 'database schema and file '
                                . 'permissions.') . '</p>',
                        ],
                    ],
                ],
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
