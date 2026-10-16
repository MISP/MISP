<?php
App::uses('AppController', 'Controller');
App::uses('MispTheme', 'MispTheme');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ModuleCredentials', 'Tools/AnalystProfile');
App::uses('OrgGradeTool', 'Tools/AnalystProfile');
App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');
App::uses('ValueVerdictDiffTool', 'Tools/ValueIntelligence');
App::uses('ValueExclusionTool', 'Tools/ValueIntelligence');

/**
 * The UI for owning an Analyst Profile: an index that names the profile
 * in force, a read-only viewer, a per-section editor, a one-click fork,
 * and a simulator that scores a candidate profile against a real value
 * before anything is saved.
 *
 * prd/analyst-profile/09-editor.md is the specification. Phase 1 built
 * the store and deliberately shipped no controller, so this file is also
 * where `queryACL/findMissingFunctionNames` finally has something to
 * check (02-store.md §6, amended).
 *
 * ## This is phase 8a, and it renders nothing
 *
 * §1.1 splits the editor into a contract, three prototypes and a
 * wiring pass, and **every action here answers with its view-model as
 * JSON**. Not as scaffolding: an analyst profile is one JSON document,
 * export and import are the sharing path, and a profile the API cannot
 * read is a profile no automation can review. What 8c adds is the HTML
 * branch — the same arrays, handed to the templates of whichever design
 * gets picked — so nothing here has to be unpicked to get there.
 *
 * The consequence worth stating: **a browser gets JSON today.** That is
 * the honest state of a phase whose whole point is that no design
 * decision has been made yet.
 *
 * ## There is no `add`
 *
 * D5 makes a fork a frozen copy and 02-store.md §5 makes it the only
 * way in — the shipped default is uneditable by an ordinary analyst, so
 * a blank-slate form would be a second entrance to a room with one
 * door, and an empty `parameters` document scores nothing and names no
 * signal. A new profile is a fork of one that already works, or an
 * `import` of somebody else's.
 *
 * ## Nothing here decides who may edit what
 *
 * `AnalystProfile::isEditableByCurrentUser()` does, and it is asked on
 * every write. D13 put the rule in the model on purpose: the ACL is a
 * per-action whitelist and cannot express *"your own, or your
 * organisation's if you are an org admin"*, so an ACL entry that tried
 * would be a second opinion about the same question — and two of those
 * is how the looser one becomes the answer.
 */
class AnalystProfilesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $uses = array('AnalystProfile');

    /** Where these views and elements live. */
    const THEME = 'Overmind';

    /** The most values an analyst may pin to the simulator (§2.2). */
    const COMPARISON_LIMIT = 8;

    /** Where the pinned set lives, per user. */
    const COMPARISON_SETTING = 'analyst_profile_comparison_set';

    /**
     * The sections `ValueIntelligence::verdictContextFor()` reads off the
     * profile, and so the ones a simulation may not share a context
     * across: `exclusions` (the exclusion plan and the evidence
     * window), `reference` (source grades, module grades, warninglist
     * categories) and `galaxies` (the attribution priority).
     */
    const CONTEXT_SECTIONS = array(
        'exclusions', 'reference', 'galaxies',
    );

    /**
     * The editor posts field names the form helper cannot produce.
     *
     * A signal id contains dots, an attribute type a pipe, an
     * organisation key is a uuid — so the form writes its own bracket
     * names, and `SecurityComponent`'s field hash, which is built from
     * the names the helper emitted, can only ever fail against them.
     * **CSRF stays on**: it is the check that matters here, and it is
     * checked separately from the field hash.
     *
     * `pin` and `unpin` are on the list for a second reason. The
     * editor pins without leaving the page, so its press posts the
     * editor's own form — that is where the CSRF token is, and a
     * separate form for it inside the editor's form is markup a
     * browser discards. The hash that arrives is therefore the one
     * `edit` minted, over a different URL, and it cannot match.
     *
     * @return void
     */
    public function beforeFilter()
    {
        parent::beforeFilter();
        if (in_array($this->request->params['action'],
            array('edit', 'import', 'simulate', 'pin', 'unpin'), true)
        ) {
            $this->Security->validatePost = false;
        }
        $this->_csrfTokenHeaderOnly(['grade']);
        /*
         * The editor posts more than once per page: every field change
         * recomputes the bench, and a pin posts beside it. A single-use
         * CSRF key makes the *first* of those spend the token the rest
         * need, so the second press is a blackhole — which is exactly
         * what the Value Intelligence page hit
         * (`ValuesController::beforeFilter()`), and this is the same
         * fix. A stable per-session key is the synchroniser-token
         * pattern; CSRF turns on an attacker being unable to read the
         * token cross-origin, never on its being fresh.
         */
        $this->Security->csrfUseOnce = false;
    }

    /**
     * Render under the theme these pages live in, whoever is asking.
     *
     * They have one implementation and it is under `Overmind`, so
     * naming it here says where the files are rather than overriding
     * anybody's preference. A reader whose own theme carries the
     * directory keeps it.
     *
     * @return void
     */
    public function beforeRender()
    {
        parent::beforeRender();
        if (!MispTheme::carries($this->theme, 'AnalystProfiles')) {
            $this->theme = self::THEME;
            $this->viewClass = 'Theme';
        }
    }

    /**
     * Every profile this reader may see, with the one in force named
     * first and unmistakably.
     *
     * The commonest confusion this feature can create is an analyst
     * editing a profile that is not weighting their pages — they forked,
     * forgot, and their organisation's profile still wins, or their own
     * is disabled. So each row carries its *standing*: in force, or the
     * reason it is not, naming the profile that beat it.
     *
     * @return CakeResponse
     */
    public function index()
    {
        $user = $this->Auth->user();
        $board = $this->AnalystProfile->indexFor($user);
        $inForce = $board['in_force'];
        return $this->__payload(array(
            'profiles' => $board['profiles'],
            /*
             * Null is a state and not an absence: a site admin who has
             * disabled the instance default leaves every reader who owns
             * no profile with no scoring at all, and 01-profile.md §5.3
             * has the page say so rather than showing a zero.
             */
            'in_force' => $inForce === null
                ? null
                : array(
                    'id' => (int)$inForce['id'],
                    'name' => $inForce['name'],
                ),
            'scoring_off' => $inForce === null,
            /*
             * How the winner was reached, and what each scope declared
             * that did not resolve. A selection whose target has been
             * deleted or switched off falls through in silence (D45),
             * and this is where the silence is broken: the index says
             * *your selection is gone and the instance profile is
             * scoring you* rather than leaving a reader to work out why
             * the name at the top of their value page changed.
             */
            'via' => $board['resolution']['via'],
            'selections' => $board['resolution']['selections'],
            'unresolved' => $board['resolution']['unresolved'],
            'may_select_for_org' =>
                !empty($user['Role']['perm_admin']),
            'may_select_for_instance' =>
                !empty($user['Role']['perm_site_admin']),
            'loader_errors' => $this->__loaderErrors(),
            'comparison_set' => $this->__comparisonSet($user),
            'comparison_limit' => self::COMPARISON_LIMIT,
            'capabilities' => $this->__capabilities($board),
        ), 'index');
    }

    /**
     * What this instance lets a profile actually do.
     *
     * A profile can name enrichment modules its owner will never see
     * run, and a reader can wonder for a long time why hovering a value
     * shows nothing, because both are instance settings sitting above
     * the profile rather than in it. Neither is visible from any page
     * the profile is read on, so the index says so once, plainly, and
     * links a site admin to the switch.
     *
     * `Plugin.Enrichment_services_enable` is reported beside the
     * auto-run gate rather than folded into it: with modules off,
     * auto-run set to `on` runs nothing, and *off* and *on but inert*
     * are different conversations with different people.
     *
     * @param array $board The index board, for the instance selection
     * @return array
     */
    private function __capabilities(array $board)
    {
        $uuid = isset($board['resolution']['selections']['instance'])
            ? $board['resolution']['selections']['instance']
            : null;
        $named = null;
        foreach ($board['profiles'] as $profile) {
            if ($uuid !== null && $profile['uuid'] === $uuid) {
                $named = $profile;
                break;
            }
        }
        $problem = isset($board['resolution']['unresolved']['instance'])
            ? $board['resolution']['unresolved']['instance']
            : null;

        return array(
            'hover_card' => array(
                'setting' => 'MISP.value_hover_card',
                'tab' => 'MISP',
                'on' => (bool)Configure::read('MISP.value_hover_card'),
            ),
            'enrichment_modules' => array(
                'setting' => 'Plugin.Enrichment_services_enable',
                'tab' => 'Plugin',
                'on' => (bool)Configure::read(
                    'Plugin.Enrichment_services_enable'),
            ),
            'enrichment_auto_run' => array(
                'setting' => 'Plugin.ValueIntelligence_enrichment_auto_run',
                'tab' => 'Plugin',
                'state' => (string)Configure::read(
                    'Plugin.ValueIntelligence_enrichment_auto_run'),
            ),
            'instance_profile' => array(
                'setting' => 'Plugin.ValueIntelligence_instance_profile',
                'tab' => 'Plugin',
                'uuid' => $uuid,
                'name' => $named === null ? null : $named['name'],
                'id' => $named === null ? null : $named['id'],
                'reason' => $problem === null ? null : $problem['reason'],
            ),
        );
    }

    /**
     * One profile, read-only, section by section.
     *
     * Takes the simulator's optional `?value=` so each weight can be
     * shown beside the contribution it produced on that value. Without
     * one the contribution column stays empty rather than inventing a
     * number.
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function view($id = null)
    {
        $user = $this->Auth->user();
        $profile = $this->__profileOr404($user, $id);
        return $this->__payload(
            $this->__board($user, $profile, false),
            'view'
        );
    }

    /**
     * The per-section editor. GET describes the form; POST applies it.
     *
     * Three ways in, and they are deliberately different shapes:
     *
     * - `data[AnalystProfile][parameters]` — a section's fields, nested
     *   the way `AnalystProfileFormTool::merge()` expects. A section the
     *   form did not post is untouched.
     * - `data[AnalystProfile][parameters_json]` — the whole document,
     *   pasted. Replaces rather than merges, because that is what
     *   pasting a document means.
     * - `data[AnalystProfile][name]` / `[description]` — the label. Moves
     *   no counter (§4.1).
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function edit($id = null)
    {
        $user = $this->Auth->user();
        $profile = $this->__profileOr404($user, $id);
        $row = $profile['AnalystProfile'];
        if (!$this->AnalystProfile->isEditableByCurrentUser($user, $row)) {
            throw new ForbiddenException(__(
                'This profile is not yours to edit. Fork it and edit'
                . ' the copy.'
            ));
        }
        if (!$this->request->is(array('post', 'put'))) {
            return $this->__payload(
                $this->__board($user, $profile, true),
                'edit'
            );
        }

        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : $this->request->data;
        $benched = $this->__requestedValue();
        $form = new AnalystProfileFormTool();
        $stored = is_array($row['parameters']) ? $row['parameters'] : array();

        if (array_key_exists('parameters_json', $posted)) {
            $parsed = $form->parse($posted['parameters_json']);
            if (empty($parsed['ok'])) {
                $board = $this->__board($user, $profile, true);
                $board['raw'] = $posted['parameters_json'];
                $board['parse'] = array(
                    'error' => $parsed['error'],
                    'line' => isset($parsed['line'])
                        ? $parsed['line']
                        : null,
                );
                $board['open_section'] = 'raw';
                return $this->__refuse(array($parsed['error']), array(
                    'parse' => $board['parse'],
                ), array('view' => 'edit', 'vars' => $board));
            }
            $parameters = $parsed['parameters'];
        } elseif (isset($posted['parameters'])
            && is_array($posted['parameters'])
        ) {
            $parameters = $form->merge($stored, $posted['parameters']);
        } else {
            $parameters = $stored;
        }

        $checked = $form->validate($parameters);
        if (!empty($checked['errors'])) {
            $candidate = $profile;
            $candidate['AnalystProfile']['parameters'] = $parameters;
            return $this->__refuse($checked['errors'], array(
                'warnings' => $checked['warnings'],
                'bands' => $form->bandStrip($parameters),
            ), array(
                'view' => 'edit',
                'vars' => $this->__board($user, $candidate, true),
            ));
        }

        $save = array('id' => $row['id']);
        $changedParameters = $this->__canonical($parameters)
            !== $this->__canonical($stored);
        if ($changedParameters) {
            $save['parameters'] = $parameters;
        }
        foreach (array('name', 'description') as $label) {
            if (array_key_exists($label, $posted)) {
                $save[$label] = $posted[$label];
            }
        }
        $this->AnalystProfile->id = $row['id'];
        if (!$this->AnalystProfile->save(array('AnalystProfile' => $save))) {
            return $this->__refuse(
                $this->__flatten($this->AnalystProfile->validationErrors)
            );
        }
        /*
         * `revision` is the local edit counter and moves only when
         * `parameters` did (§4.1). Phase 10 keys its materialised
         * assessments on it, so a counter that moved for a rename would
         * invalidate every stored row for nothing.
         */
        if ($changedParameters) {
            $this->AnalystProfile->bumpRevision($row['id']);
        }
        $saved = $this->AnalystProfile->fetchProfile($user, $row['id']);
        return $this->__wrote(
            array(
                'saved' => true,
                'parameters_changed' => $changedParameters,
                'warnings' => $checked['warnings'],
                'profile' => $this->AnalystProfile->summarise(
                    $saved['AnalystProfile']
                ),
            ),
            $changedParameters
                ? sprintf(
                    __('Saved. %s is now at revision %s.'),
                    $saved['AnalystProfile']['name'],
                    $saved['AnalystProfile']['revision']
                )
                : __('Saved. Nothing in the document changed, so the'
                    . ' revision did not move.'),
            /*
             * The bench never leaves, and a save is the moment it
             * would: the redirect carries the value back so the pane
             * the edit was judged against is still under it.
             */
            array('action' => 'edit', $row['id'],
                '?' => $benched === null
                    ? array()
                    : array('value' => ValueUrlTool::encode($benched)))
        );
    }

    /**
     * Copy a profile into one the caller owns.
     *
     * **A user may hold one enabled profile** (phase 1 §5), so forking
     * with one already present is a decision rather than a silent
     * second row. Without `replace` this answers with the existing
     * profile named and nothing written; with it, the existing one is
     * **disabled and never deleted** — an analyst's tuned judgement is
     * not something a one-click flow may destroy (§6).
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function fork($id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $source = $this->__profileOr404($user, $id);
        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : $this->request->data;
        /*
         * `for_org` is read from the query as well as from the body,
         * because both buttons that set it put it there: the index'
         * *Fork to my organisation* is a `postLink` carrying
         * `?for_org=1`, and the profile page's is a header action,
         * which builds its own `postLink` and has no way to add a
         * field to it. Read from the body alone the flag never
         * arrived — a CakePHP 2 query string does not reach
         * `request->data` — and both buttons quietly forked to the
         * caller instead, which is the opposite scope from the one
         * they name. The POST is still the Security component's to
         * accept; this only says where the flag may be written.
         */
        $forOrg = !empty($posted['for_org'])
            || !empty($this->request->query['for_org']);
        $replace = !empty($posted['replace']);
        $name = isset($posted['name']) && trim((string)$posted['name']) !== ''
            ? trim((string)$posted['name'])
            : null;

        if ($forOrg && empty($user['Role']['perm_admin'])
            && empty($user['Role']['perm_site_admin'])
        ) {
            throw new ForbiddenException(__(
                'Forking to the organisation is an org-admin action,'
                . ' because it changes what colleagues read.'
            ));
        }

        $existing = $this->__enabledFor($user, $forOrg);
        if ($existing !== null && !$replace) {
            return $this->__confirm(array(
                'confirm' => 'replace',
                'existing' => $this->AnalystProfile->summarise($existing),
                'affects' => $forOrg ? $this->__orgReaders($user) : null,
                'message' => $forOrg
                    ? sprintf(
                        __('Your organisation already has an enabled'
                            . ' profile, %s. Replacing it disables it —'
                            . ' it is not deleted — and the fork becomes'
                            . ' the one in force.'),
                        $existing['name']
                    )
                    : sprintf(
                        __('You already have an enabled profile, %s.'
                            . ' Replacing it disables it — it is not'
                            . ' deleted — and the fork becomes the one'
                            . ' in force.'),
                        $existing['name']
                    ),
            ), array(
                'title' => $forOrg
                    ? __('Fork to my organisation')
                    : __('Fork to me'),
                'url' => array('action' => 'fork', $id),
                'fields' => array(
                    'replace' => 1,
                    'for_org' => $forOrg ? 1 : 0,
                ),
                'confirm_label' => $forOrg
                    ? __('Replace my organisation\'s profile')
                    : __('Replace my current profile'),
                'cancel' => array('action' => 'index'),
            ));
        }
        if ($existing !== null) {
            $this->AnalystProfile->id = $existing['id'];
            if (!$this->AnalystProfile->saveField('enabled', 0)) {
                return $this->__refuse(array(__(
                    'The profile in force could not be disabled, so'
                    . ' nothing was forked.'
                )));
            }
        }
        $fork = $this->AnalystProfile->forkProfile($user, $id, $name,
            $forOrg);
        if (empty($fork)) {
            /*
             * The source profile is still enabled or not, exactly as the
             * caller left it — except in the one case where it was just
             * disabled to make room. Re-enabling it is the honest
             * rollback: a failed fork must not leave a reader with no
             * profile at all.
             */
            if ($existing !== null) {
                $this->AnalystProfile->id = $existing['id'];
                $this->AnalystProfile->saveField('enabled', 1);
            }
            return $this->__refuse($this->__flatten(
                $this->AnalystProfile->validationErrors
            ) ?: array(__('The fork could not be saved.')));
        }
        return $this->__wrote(array(
            'forked' => true,
            /*
             * With `enabled` corrected, because `$existing` was read
             * before it was disabled and reporting a replaced profile
             * as still enabled is the same quiet lie this feature keeps
             * refusing to tell elsewhere.
             */
            'replaced' => $existing === null
                ? null
                : array('enabled' => false)
                    + $this->AnalystProfile->summarise($existing),
            'profile' => $this->AnalystProfile->summarise($fork['AnalystProfile']),
            'source' => $this->AnalystProfile->summarise($source['AnalystProfile']),
        ),
            $existing === null
                ? sprintf(
                    __('Forked. %s is yours and is the one in force.'),
                    $fork['AnalystProfile']['name']
                )
                : sprintf(
                    __('Forked. %1$s is now in force and %2$s is'
                        . ' disabled — not deleted.'),
                    $fork['AnalystProfile']['name'],
                    $existing['name']
                ),
            array('action' => 'edit', $fork['AnalystProfile']['id'])
        );
    }

    /**
     * Enable a profile, running the one-enabled swap in reverse.
     *
     * The invariant means enabling one disables the other, so the
     * response says which — a swap the reader did not ask for and
     * cannot see is the whole failure mode §3's standing exists to
     * prevent.
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function enable($id = null)
    {
        return $this->__setEnabled($id, true);
    }

    /**
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function disable($id = null)
    {
        return $this->__setEnabled($id, false);
    }

    /**
     * Use a profile without forking it (D45).
     *
     * `?scope=user` (the default) writes the uuid to this reader's
     * `analyst_profile` user setting, `?scope=org` to
     * `analyst_profile_selections`, and `?scope=instance` to the site
     * setting. D13 decides who may do which and there is still no new
     * permission flag: choosing for yourself needs no grant, choosing
     * for an organisation is `perm_admin`, choosing for the instance is
     * site-admin only.
     *
     * The instance scope is a site setting rather than a row, so it is
     * written through `Server::serverSettingsSaveValue()` — the same
     * path the settings page uses — and gets the same validator.
     *
     * @param int|string|null $id id or uuid
     * @return CakeResponse
     */
    public function select($id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $scope = $this->__selectionScope();
        $profile = $this->__profileOr404($user, $id);
        $row = $profile['AnalystProfile'];

        if ($scope === 'instance') {
            return $this->__selectForInstance($row);
        }
        $chosen = $this->AnalystProfile->selectProfile(
            $user,
            $scope,
            $row['uuid']
        );
        if ($chosen === null) {
            return $this->__refuse(array(
                $this->AnalystProfile->selectionError
                    ?: __('The selection could not be saved.'),
            ));
        }
        $inForce = $this->AnalystProfile->resolveFor($user);
        $displaced = $chosen['displaced'];
        return $this->__wrote(array(
            'scope' => $scope,
            'selected' => $this->AnalystProfile->summarise($row),
            'displaced' => $displaced === null
                ? null
                : array('enabled' => false)
                    + $this->AnalystProfile->summarise($displaced),
            'in_force' => $inForce === null
                ? null
                : $this->AnalystProfile->summarise($inForce),
        ),
            $displaced === null
                ? sprintf(
                    $scope === 'org'
                        ? __('%s is now your organisation\'s profile.')
                        : __('%s is now your profile.'),
                    $row['name']
                )
                : sprintf(
                    __('%1$s is now in force, so %2$s was disabled — one'
                        . ' answer per scope, and nothing was deleted.'),
                    $row['name'],
                    $displaced['name']
                ),
            array('action' => 'index')
        );
    }

    /**
     * Stop selecting, so the next scope answers.
     *
     * @return CakeResponse
     */
    public function deselect()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $scope = $this->__selectionScope();
        if ($scope === 'instance') {
            return $this->__refuse(array(__(
                'The instance always names a profile. Point it at another'
                . ' one, or disable the one it names to switch scoring'
                . ' off.'
            )));
        }
        $this->AnalystProfile->clearSelection($user, $scope);
        $inForce = $this->AnalystProfile->resolveFor($user);
        return $this->__wrote(array(
            'scope' => $scope,
            'in_force' => $inForce === null
                ? null
                : $this->AnalystProfile->summarise($inForce),
        ),
            $inForce === null
                ? __('The selection is cleared, and nothing scores your'
                    . ' pages now.')
                : sprintf(
                    __('The selection is cleared. %s scores your pages'
                        . ' now.'),
                    $inForce['name']
                ),
            array('action' => 'index')
        );
    }

    /**
     * Share a site admin's own profile with every user, who may then read,
     * fork and select it.
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function share($id = null)
    {
        return $this->__setShared($id, true);
    }

    /**
     * Withdraw a shared profile. Readers who selected it fall through to
     * their next scope; it goes back to its owner disabled.
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function unshare($id = null)
    {
        return $this->__setShared($id, false);
    }

    /**
     * @param int|string|null $id
     * @param bool $shared
     * @return CakeResponse
     */
    private function __setShared($id, $shared)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $this->__profileOr404($user, $id);
        $row = $this->AnalystProfile->setShared($user, $id, $shared);
        if ($row === null) {
            return $this->__refuse(array($this->AnalystProfile->shareError));
        }
        return $this->__wrote(
            array('profile' => $this->AnalystProfile->summarise($row)),
            sprintf(
                $shared
                    ? __('%s is shared: every user can now read, fork and select it.')
                    : __('%s is no longer shared, and is disabled.'),
                $row['name']
            ),
            array('action' => 'view', $row['id'])
        );
    }

    /**
     * Which scope this write is for, checked against D13's permissions.
     *
     * @return string
     */
    private function __selectionScope()
    {
        $scope = 'user';
        if (!empty($this->request->data['AnalystProfile']['scope'])) {
            $scope = $this->request->data['AnalystProfile']['scope'];
        } elseif (!empty($this->request->data['scope'])) {
            $scope = $this->request->data['scope'];
        } elseif (!empty($this->request->query['scope'])) {
            $scope = $this->request->query['scope'];
        }
        if (!in_array($scope, array('user', 'org', 'instance'), true)) {
            throw new MethodNotAllowedException(__(
                'A profile is chosen for you, for your organisation or for'
                . ' the instance.'
            ));
        }
        $user = $this->Auth->user();
        if ($scope === 'org' && empty($user['Role']['perm_admin'])) {
            throw new ForbiddenException(__(
                'Choosing what your colleagues are scored by is an'
                . ' organisation admin action.'
            ));
        }
        if ($scope === 'instance' && empty($user['Role']['perm_site_admin'])) {
            throw new ForbiddenException(__(
                'Choosing what the whole instance is scored by is a site'
                . ' admin action.'
            ));
        }
        return $scope;
    }

    /**
     * @param array $row
     * @return CakeResponse
     */
    private function __selectForInstance(array $row)
    {
        $Server = ClassRegistry::init('Server');
        $verdict = $Server->testAnalystProfileUuid($row['uuid']);
        if ($verdict !== true) {
            return $this->__refuse(array($verdict));
        }
        if (!$Server->serverSettingsSaveValue(
            'Plugin.ValueIntelligence_instance_profile',
            $row['uuid']
        )) {
            return $this->__refuse(array(__(
                'The setting could not be written. Check that the'
                . ' configuration file is writable by the web server.'
            )));
        }
        Configure::write(
            'Plugin.ValueIntelligence_instance_profile',
            $row['uuid']
        );
        $this->AnalystProfile->resetResolution();
        $inForce = $this->AnalystProfile->resolveFor($this->Auth->user());
        return $this->__wrote(array(
            'scope' => 'instance',
            'selected' => $this->AnalystProfile->summarise($row),
            'in_force' => $inForce === null
                ? null
                : $this->AnalystProfile->summarise($inForce),
        ),
            sprintf(
                __('%s is now the instance profile, for every reader whose'
                    . ' organisation and account have chosen none.'),
                $row['name']
            ),
            array('action' => 'index')
        );
    }

    /**
     * @param int|string|null $id
     * @param bool $enabled
     * @return CakeResponse
     */
    private function __setEnabled($id, $enabled)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $profile = $this->__profileOr404($user, $id);
        $row = $profile['AnalystProfile'];
        if (!$this->AnalystProfile->isEditableByCurrentUser($user, $row)) {
            throw new ForbiddenException(__(
                'This profile is not yours to enable or disable.'
            ));
        }
        $displaced = null;
        if ($enabled && empty($row['default']) && empty($row['shared'])) {
            $displaced = $this->__enabledFor($user, !empty($row['org_id']));
            if ($displaced !== null
                && (int)$displaced['id'] === (int)$row['id']
            ) {
                $displaced = null;
            } elseif ($displaced !== null) {
                $this->AnalystProfile->id = $displaced['id'];
                $this->AnalystProfile->saveField('enabled', 0);
            }
        }
        $this->AnalystProfile->id = $row['id'];
        if (!$this->AnalystProfile->saveField('enabled', $enabled ? 1 : 0)) {
            if ($displaced !== null) {
                $this->AnalystProfile->id = $displaced['id'];
                $this->AnalystProfile->saveField('enabled', 1);
            }
            return $this->__refuse($this->__flatten(
                $this->AnalystProfile->validationErrors
            ) ?: array(__('The profile could not be saved.')));
        }
        /*
         * Re-resolved rather than reasoned about: the swap has just
         * moved which profile wins, and the caller's next question is
         * *so what is in force now*. `$row` and `$displaced` were both
         * read before the writes, so their `enabled` is corrected here
         * rather than reported stale.
         */
        $inForce = $this->AnalystProfile->resolveFor($user);
        return $this->__wrote(array(
            'enabled' => $enabled,
            'profile' => array('enabled' => $enabled)
                + $this->AnalystProfile->summarise($row),
            'displaced' => $displaced === null
                ? null
                : array('enabled' => false) + $this->AnalystProfile->summarise($displaced),
            'in_force' => $inForce === null
                ? null
                : $this->AnalystProfile->summarise($inForce),
        ),
            $displaced === null
                ? sprintf(
                    $enabled
                        ? __('%s is enabled.')
                        : __('%s is disabled.'),
                    $row['name']
                )
                : sprintf(
                    __('%1$s is enabled, so %2$s was disabled — you may'
                        . ' hold one at a time, and nothing was'
                        . ' deleted.'),
                    $row['name'],
                    $displaced['name']
                ),
            array('action' => 'index')
        );
    }

    /**
     * Delete a profile. Never the default, and never as a side effect —
     * §6 keeps deletion an explicit action for the same reason replace
     * only disables.
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function delete($id = null)
    {
        if (!$this->request->is(array('post', 'delete'))) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST or DELETE requests.'
            ));
        }
        $user = $this->Auth->user();
        $profile = $this->__profileOr404($user, $id);
        $row = $profile['AnalystProfile'];
        if (!empty($row['default'])) {
            throw new ForbiddenException(__(
                'The instance default is the fall-back every reader who'
                . ' owns no profile resolves to. It can be disabled;'
                . ' it cannot be deleted.'
            ));
        }
        if (!$this->AnalystProfile->isEditableByCurrentUser($user, $row)) {
            throw new ForbiddenException(__(
                'This profile is not yours to delete.'
            ));
        }
        if (!$this->AnalystProfile->delete($row['id'])) {
            return $this->__refuse($this->__flatten(
                $this->AnalystProfile->validationErrors
            ) ?: array(__('The profile could not be deleted.')));
        }
        return $this->__wrote(
            array(
                'deleted' => true,
                'profile' => $this->AnalystProfile->summarise($row),
            ),
            sprintf(__('%s is deleted.'), $row['name']),
            array('action' => 'index')
        );
    }

    /**
     * The JSON, as a download.
     *
     * `uuid` and `version` ride along, because an import decides what to
     * do about a collision by reading them (02-store.md §6).
     *
     * @param int|string|null $id
     * @return CakeResponse
     */
    public function export($id = null)
    {
        $user = $this->Auth->user();
        $profile = $this->__profileOr404($user, $id);
        $row = $profile['AnalystProfile'];
        $json = json_encode($this->__document($row),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $filename = sprintf(
            'analyst-profile-%s.json',
            trim(preg_replace('/[^a-z0-9]+/', '-',
                strtolower($row['name'])), '-')
        );
        return $this->RestResponse->viewData($json, 'application/json',
            false, true, $filename);
    }

    /**
     * Somebody else's profile, as a copy of their judgement.
     *
     * **A uuid that already exists locally is re-minted, never
     * overwritten** (02-store.md §6). An imported profile is a copy of
     * somebody else's judgement, and overwriting a local row of the same
     * uuid would silently rewrite the profile the assessment has been
     * naming.
     *
     * @return CakeResponse
     */
    public function import()
    {
        $user = $this->Auth->user();
        if (!$this->request->is('post')) {
            /*
             * A browser has to be given the form before it can post
             * one. REST keeps the refusal: there is nothing to GET
             * here for a caller that already holds a document.
             */
            if ($this->_isRest()) {
                throw new MethodNotAllowedException(__(
                    'This endpoint only accepts POST requests.'
                ));
            }
            return $this->__payload(array(
                'can_import_for_org' => !empty($user['Role']['perm_admin'])
                    || !empty($user['Role']['perm_site_admin']),
                'holds_enabled' => $this->__enabledFor($user, false) !== null,
            ), 'import');
        }
        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : $this->request->data;
        $raw = null;
        foreach (array('json', 'parameters_json', 'document') as $key) {
            if (isset($posted[$key]) && is_string($posted[$key])) {
                $raw = $posted[$key];
                break;
            }
        }
        $document = $raw === null ? $posted : json_decode($raw, true);
        if (!is_array($document)) {
            return $this->__refuse(array(__(
                'The import must be a JSON object with `name` and'
                . ' `parameters`.'
            )));
        }
        if (empty($document['parameters'])
            || !is_array($document['parameters'])
        ) {
            return $this->__refuse(array(__(
                '`parameters` is missing, so there would be nothing to'
                . ' score with.'
            )));
        }
        $form = new AnalystProfileFormTool();
        $checked = $form->validate($document['parameters']);
        if (!empty($checked['errors'])) {
            return $this->__refuse($checked['errors'],
                array('warnings' => $checked['warnings']));
        }
        $forOrg = !empty($posted['for_org']);
        if ($forOrg && empty($user['Role']['perm_admin'])
            && empty($user['Role']['perm_site_admin'])
        ) {
            throw new ForbiddenException(__(
                'Importing to the organisation is an org-admin action.'
            ));
        }
        $existing = $this->__enabledFor($user, $forOrg);
        $reuuid = false;
        $uuid = isset($document['uuid']) ? $document['uuid'] : null;
        if ($uuid !== null && Validation::uuid($uuid)) {
            $clash = $this->AnalystProfile->find('first', array(
                'conditions' => array('AnalystProfile.uuid' => $uuid),
                'fields' => array('AnalystProfile.id'),
                'recursive' => -1,
            ));
            if (!empty($clash)) {
                $reuuid = true;
            }
        } else {
            $reuuid = true;
        }
        $save = array(
            'uuid' => $reuuid ? CakeText::uuid() : $uuid,
            'name' => isset($document['name']) && $document['name'] !== ''
                ? $document['name']
                : __('Imported profile'),
            'description' => isset($document['description'])
                ? $document['description']
                : null,
            'parameters' => $document['parameters'],
            'user_id' => $forOrg ? null : $user['id'],
            'org_id' => $forOrg ? $user['org_id'] : null,
            'default' => 0,
            /*
             * An import lands disabled when the owner already holds an
             * enabled profile, rather than refusing or displacing one.
             * Import is how a profile is *reviewed* before it is
             * adopted — §8 makes it the sharing path — and a reviewer
             * should be able to simulate it without their own pages
             * changing underneath them first.
             */
            'enabled' => $existing === null ? 1 : 0,
            'version' => isset($document['version'])
                ? (int)$document['version']
                : 1,
            'revision' => 1,
        );
        $this->AnalystProfile->create();
        if (!$this->AnalystProfile->save(array('AnalystProfile' => $save))) {
            return $this->__refuse($this->__flatten(
                $this->AnalystProfile->validationErrors
            ) ?: array(__('The profile could not be imported.')));
        }
        $imported = $this->AnalystProfile->fetchProfile($user,
            $this->AnalystProfile->id);
        return $this->__wrote(array(
            'imported' => true,
            're_uuided' => $reuuid,
            'enabled' => $existing === null,
            'blocked_by' => $existing === null
                ? null
                : $this->AnalystProfile->summarise($existing),
            'warnings' => $checked['warnings'],
            'profile' => $this->AnalystProfile->summarise($imported['AnalystProfile']),
        ),
            $existing === null
                ? sprintf(
                    __('Imported. %s is yours and is the one in force.'),
                    $imported['AnalystProfile']['name']
                )
                : sprintf(
                    __('Imported. %1$s is disabled, because %2$s is'
                        . ' still in force — simulate it before you'
                        . ' adopt it.'),
                    $imported['AnalystProfile']['name'],
                    $existing['name']
                ),
            array('action' => 'edit', $imported['AnalystProfile']['id'])
        );
    }

    /**
     * Load the shipped defaults, the way every other model that reads
     * shipped JSON is driven.
     *
     * @param bool|string $force
     * @return CakeResponse
     */
    public function update($force = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $outcome = $this->AnalystProfile->updateDefaults(
            $force === true || $force === 'true' || $force === '1'
        );
        return $this->__wrote(
            array('outcomes' => $outcome),
            __('The shipped defaults were loaded.'),
            array('action' => 'index')
        );
    }

    /**
     * What a candidate profile would do to a value, beside what the
     * profile in force does to it.
     *
     * **It computes and it does not save.** The candidate arrives as
     * `parameters_json` or as a section form merged over the stored
     * document, is scored in memory, and nothing is written — which is
     * why the simulator works on a profile the analyst cannot edit,
     * including the instance default. That is how somebody decides
     * whether they need a fork at all.
     *
     * @param int|string|null $id The candidate's base profile
     * @return CakeResponse
     */
    public function simulate($id = null)
    {
        $user = $this->Auth->user();
        $base = $this->__profileOr404($user, $id);
        $row = $base['AnalystProfile'];
        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : array();
        $form = new AnalystProfileFormTool();
        $stored = is_array($row['parameters']) ? $row['parameters'] : array();

        $candidateParameters = $stored;
        $parseError = null;
        if (isset($posted['parameters_json'])) {
            $parsed = $form->parse($posted['parameters_json']);
            if (empty($parsed['ok'])) {
                $parseError = $parsed;
            } else {
                $candidateParameters = $parsed['parameters'];
            }
        } elseif (isset($posted['parameters'])
            && is_array($posted['parameters'])
        ) {
            $candidateParameters = $form->merge($stored,
                $posted['parameters']);
        }
        if ($parseError !== null) {
            return $this->__refuse(array($parseError['error']), array(
                'parse' => array(
                    'error' => $parseError['error'],
                    'line' => isset($parseError['line'])
                        ? $parseError['line']
                        : null,
                ),
            ), array('redirect' => array('action' => 'edit', $id)));
        }

        $checked = $form->validate($candidateParameters);
        $simulation = $this->__simulation($user, $row, $candidateParameters);
        /*
         * The editor's bench is this computation, so the editor asks
         * for it again whenever a field changes — as the fragment
         * alone, since the rest of the page is already on screen.
         * One producer: the pane and the page it expands into cannot
         * disagree, and neither can the pane and itself after an edit.
         */
        if (!$this->_isRest() && $this->request->is('ajax')) {
            $this->set('bench', $simulation);
            $this->set('bands', $form->bandStrip($candidateParameters));
            $this->set('full', false);
            $this->set('profileId', $row['id']);
            /*
             * The relevance curve rides back with the bench, because it
             * is the one figure on the page that is a picture of a
             * field rather than of the document's effect — and it was
             * the one thing an edit did not move. Built from the posted
             * document like everything else in this response, so a
             * decay speed typed and not saved draws the line it makes.
             */
            $this->set($this->__curveFor($user, $candidateParameters,
                $simulation));
            $this->layout = false;
            return $this->render('/Elements/AnalystProfiles/bench');
        }
        return $this->__payload(
            $simulation + array(
                'candidate_valid' => empty($checked['errors']),
                'errors' => $checked['errors'],
                'warnings' => $checked['warnings'],
                'bands' => $form->bandStrip($candidateParameters),
            ),
            'simulate'
        );
    }

    /**
     * One candidate document, scored against the profile in force over
     * every value on the bench.
     *
     * **Shared with the editor**, which is not an optimisation but the
     * design: §2 exists because MISP already shipped a simulator that
     * was a destination, and the bench in the right-hand pane of
     * `edit` is this same computation. One producer, so the pane and
     * the page it expands into cannot disagree.
     *
     * @param array $user
     * @param array $row The base profile, unwrapped
     * @param array $candidateParameters The document to score
     * @return array
     */
    private function __simulation(array $user, array $row,
        array $candidateParameters
    ) {
        $inForce = $this->AnalystProfile->resolveFor($user);
        $candidate = $row;
        $candidate['parameters'] = $candidateParameters;

        $values = $this->__simulationValues($user);
        $focus = $this->__requestedValue();
        if ($focus !== null) {
            $values = array_values(array_unique(
                array_merge(array($focus), $values)
            ));
        }
        $values = array_slice($values, 0, self::COMPARISON_LIMIT + 1);

        $this->loadModel('ValueIntelligence');
        $engine = new ValueVerdictTool($this->ValueIntelligence);
        $builds = 0;
        $rows = array();
        $detail = null;
        foreach ($values as $index => $value) {
            $scored = $this->__scorePair($engine, $user, $value, $inForce,
                $candidate, $builds);
            $rows[] = ValueVerdictDiffTool::headline(
                $value,
                $scored['before'],
                $scored['after']
            );
            if ($index === 0) {
                $detail = ValueVerdictDiffTool::diff(
                    $scored['before'],
                    $scored['after']
                );
            }
        }
        return array(
            'base' => $this->AnalystProfile->summarise($row),
            'in_force' => $inForce === null
                ? null
                : $this->AnalystProfile->summarise($inForce),
            /*
             * A simulation against nothing is not a simulation. When the
             * reader has pinned no values and arrived with none, the
             * honest answer is the instruction, not an empty table.
             */
            'values' => $values,
            'focus' => $focus,
            'detail' => $detail,
            /*
             * The dates the benched value's axis is built on, for the
             * same table the value page's Lifetime card draws. Only for
             * the benched value — it is one aggregate, and the other
             * rows of the comparison are headlines rather than
             * explanations.
             */
            'dates' => empty($values)
                ? null
                : ClassRegistry::init('Value')->timelineFactsFor(
                    $user,
                    $values[0]
                ),
            'comparison' => $rows,
            'comparison_set' => $this->__comparisonSet($user),
            'context_builds' => $builds,
        );
    }

    /**
     * Grade an organisation in the reader's own profile.
     *
     * Posted `grade` is A…G or `unrated`; `fork=1` agrees to copying the
     * profile in force when it is not the reader's, which is otherwise
     * answered with 409 and the target to ask about.
     *
     * @param int|string|null $orgId id or uuid
     * @return CakeResponse
     */
    public function grade($orgId = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $this->loadModel('Organisation');
        $org = $this->Organisation->find('first', [
            'conditions' => Validation::uuid($orgId)
                ? ['Organisation.uuid' => $orgId]
                : ['Organisation.id' => (int)$orgId],
            'fields' => ['id', 'uuid', 'name'],
            'recursive' => -1,
        ]);
        if (empty($org)
            || !$this->Organisation->canSee($user, $org['Organisation']['id'])
        ) {
            throw new NotFoundException(__('Invalid organisation'));
        }
        $org = $org['Organisation'];
        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : $this->request->data;
        $parsed = OrgGradeTool::parse($posted['grade'] ?? null);
        if (!$parsed['ok']) {
            throw new BadRequestException(__(
                'A grade is A to G, or "unrated" to remove one.'
            ));
        }
        $written = $this->AnalystProfile->gradeOrganisation(
            $user,
            $org['uuid'],
            $parsed['grade'],
            !empty($posted['fork'])
        );
        $orgSummary = [
            'id' => (int)$org['id'],
            'uuid' => $org['uuid'],
            'name' => $org['name'],
        ];
        if (empty($written['ok'])) {
            if (!empty($written['needs_fork'])) {
                $response = $this->RestResponse->viewData([
                    'needs_fork' => true,
                    'message' => $written['error'],
                    'org' => $orgSummary,
                    'target' => $written['target'],
                ], 'json');
                $response->statusCode(409);
                return $response;
            }
            return $this->RestResponse->saveFailResponse(
                'AnalystProfiles', 'grade', $org['id'],
                [$written['error']], 'json'
            );
        }
        return $this->RestResponse->viewData([
            'org' => $orgSummary,
            'grade' => $parsed['grade'],
            'previous' => $written['previous'],
            'changed' => $written['changed'],
            'forked' => $written['forked'],
            'profile' => $this->AnalystProfile->summarise($written['profile']),
        ], 'json');
    }

    /**
     * Add a value to this reader's comparison set.
     *
     * @param string|null $b64value
     * @return CakeResponse
     */
    public function pin($b64value = null)
    {
        return $this->__setPinned($b64value, true);
    }

    /**
     * @param string|null $b64value
     * @return CakeResponse
     */
    public function unpin($b64value = null)
    {
        return $this->__setPinned($b64value, false);
    }

    /**
     * @param string|null $b64value
     * @param bool $pinned
     * @return CakeResponse
     */
    private function __setPinned($b64value, $pinned)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $user = $this->Auth->user();
        $value = $this->__decodeValue($b64value);
        $set = $this->__comparisonSet($user);
        $set = array_values(array_filter($set, function ($pinnedValue) use ($value) {
            return $pinnedValue !== $value;
        }));
        if ($pinned) {
            /*
             * Newest first and capped, so pinning a ninth value drops
             * the oldest rather than refusing — the set is a working
             * shortlist, not a registry, and a refusal would make the
             * analyst prune before they could compare.
             */
            array_unshift($set, $value);
            $set = array_slice($set, 0, self::COMPARISON_LIMIT);
        }
        $this->loadModel('UserSetting');
        $this->UserSetting->setSettingInternal($user['id'],
            self::COMPARISON_SETTING, $set);
        $written = array(
            'pinned' => $pinned,
            'value' => $value,
            'comparison_set' => $set,
            'limit' => self::COMPARISON_LIMIT,
        );
        /*
         * The editor pins from beside the document it is editing and
         * redraws the bench itself, so following a redirect back would
         * re-render the whole page to throw it away — and throw the
         * unsaved edits away with it.
         */
        if (!$this->_isRest() && $this->request->is('ajax')) {
            return $this->RestResponse->viewData($written, 'application/json');
        }
        return $this->__wrote(
            $written,
            $pinned
                ? sprintf(
                    __('%s is pinned, and every profile change is now'
                        . ' judged against it too.'),
                    $value
                )
                : sprintf(__('%s is unpinned.'), $value),
            $this->referer(array('action' => 'index'), true)
        );
    }

    /**
     * Score one value under two profiles, building the context once per
     * distinct context plan.
     *
     * **The candidate can change the context, not only the score.**
     * `exclusions` is applied by the context builder — `orgs.own` is a
     * query predicate in `Value::conditionsFor()` — so two profiles
     * whose exclusion sections differ are two different sets of rows,
     * and scoring both from one context would show a diff no saved
     * profile could reproduce. When the sections agree, which is the
     * common case of editing a weight, one build serves both.
     *
     * **And `exclusions` is not the only such section.** It was the
     * only one when this was written; phase 6 then put the source
     * grades in the context (`trust`), and `reference` and `galaxies`
     * reach it too. Sharing the context on an `exclusions` match alone
     * scored the candidate against the *saved* profile's trust block,
     * so grading an organisation moved nothing on the bench until the
     * edit was saved — the one state the simulator exists to show.
     * `CONTEXT_SECTIONS` is the list, and it belongs beside
     * `ValueIntelligence::verdictContextFor()`'s reads of `$profile`.
     *
     * @param ValueVerdictTool $engine
     * @param array $user
     * @param string $value
     * @param array|null $inForce
     * @param array $candidate
     * @param int $builds Incremented per context built, so the response
     *                    can report what the run actually cost
     * @return array `before` and `after`
     */
    private function __scorePair(ValueVerdictTool $engine, array $user, $value,
        $inForce, array $candidate, &$builds
    ) {
        $shared = $this->__contextSignature($inForce)
            === $this->__contextSignature($candidate);
        $context = $this->ValueIntelligence->verdictContextFor($user, $value,
            $inForce);
        $builds++;
        $before = $engine->assess($context, $inForce);
        if ($shared) {
            $after = $engine->assess($context, $candidate);
        } else {
            $candidateContext = $this->ValueIntelligence->verdictContextFor(
                $user, $value, $candidate);
            $builds++;
            $after = $engine->assess($candidateContext, $candidate);
        }
        return array('before' => $before, 'after' => $after);
    }

    /**
     * A profile's context-affecting sections, canonically, so two
     * profiles can be compared for whether one context serves both.
     *
     * Deliberately not the whole of `parameters`: a signal's points
     * are read by `assess()` and never by the context builder, and
     * editing a weight is what the bench does on almost every
     * keystroke. Hashing everything would double the query cost of the
     * common case to fix the uncommon one.
     *
     * @param array|null $profile
     * @return string
     */
    private function __contextSignature($profile)
    {
        $sections = array();
        foreach (self::CONTEXT_SECTIONS as $section) {
            $sections[$section] = is_array($profile)
                && isset($profile['parameters'][$section])
                ? $profile['parameters'][$section]
                : null;
        }
        return $this->__canonical($sections);
    }

    /**
     * The values a simulation runs over: the reader's pinned set.
     *
     * @param array $user
     * @return array
     */
    private function __simulationValues(array $user)
    {
        return $this->__comparisonSet($user);
    }

    /**
     * @param array $user
     * @return array
     */
    private function __comparisonSet(array $user)
    {
        $this->loadModel('UserSetting');
        $set = $this->UserSetting->getValueForUser($user['id'],
            self::COMPARISON_SETTING);
        if (!is_array($set)) {
            return array();
        }
        $out = array();
        foreach ($set as $value) {
            if (is_string($value) && $value !== '') {
                $out[] = $value;
            }
        }
        return array_slice($out, 0, self::COMPARISON_LIMIT);
    }

    /**
     * The section the caller wants open, when the link that brought
     * them here knew which one answers their question.
     *
     * @return string|null
     */
    private function __requestedSection()
    {
        if (empty($this->request->query['section'])) {
            return null;
        }
        $section = (string)$this->request->query['section'];
        if ($section === 'raw'
            || in_array($section, AnalystProfileFormTool::SECTION_ORDER, true)
        ) {
            return $section;
        }
        return null;
    }

    /**
     * The value the caller asked about, from `?value=` or a posted one.
     *
     * @return string|null
     */
    private function __requestedValue()
    {
        foreach (array('value', 'b64value') as $key) {
            if (!empty($this->request->query[$key])) {
                return $this->__decodeValue(
                    $this->request->query[$key]
                );
            }
        }
        $posted = isset($this->request->data['AnalystProfile'])
            ? $this->request->data['AnalystProfile']
            : array();
        if (!empty($posted['value'])) {
            return $this->__decodeValue($posted['value']);
        }
        return null;
    }

    /**
     * The value a request names, or a 404.
     *
     * `ValueUrlTool` owns the encoding — the Value Intelligence page mints
     * the same `?value=` and there is one implementation of the
     * alphabet question — and the refusal stays here, so this
     * endpoint's wording is its own.
     *
     * @param string|null $b64value
     * @return string
     * @throws NotFoundException
     */
    private function __decodeValue($b64value)
    {
        $value = ValueUrlTool::decode($b64value);
        if ($value === null) {
            throw new NotFoundException(__(
                'That is not a value this page can read. Values travel'
                . ' base64-encoded, because they are arbitrary strings'
                . ' in a URL.'
            ));
        }
        return $value;
    }

    /**
     * Everything `view` and `edit` describe about one profile.
     *
     * @param array $user
     * @param array $profile
     * @param bool $editable
     * @return array
     */
    /**
     * The three variables `ttl_curve` needs, from a candidate document.
     *
     * The section builder is the one place that knows how a bucket
     * block is shaped, so the curve is fed from its output rather than
     * from the raw parameters — the same reading the open editor drew
     * with, which is what makes the redrawn figure comparable to the
     * one it replaces.
     *
     * @param array $user
     * @param array $parameters The candidate document
     * @param array $simulation What `__simulation` answered for it
     * @return array Empty when the relevance section has no curve
     */
    private function __curveFor(array $user, array $parameters,
        array $simulation
    ) {
        $form = new AnalystProfileFormTool();
        $sections = $form->sections($parameters,
            $this->__sources($user, $parameters));
        foreach ($sections as $section) {
            if ($section['id'] !== 'relevance') {
                continue;
            }
            foreach ($section['blocks'] as $block) {
                if ($block['kind'] !== 'map'
                    || $block['id'] !== 'ttl_buckets'
                ) {
                    continue;
                }
                $detail = $simulation['detail'];
                return array(
                    'curveBlock' => $block,
                    'curveSection' => $section,
                    'curveRunway' => $detail !== null
                        && isset($detail['axes']['relevance']['runway'])
                            ? $detail['axes']['relevance']['runway']
                            : null,
                );
            }
        }
        return array();
    }

    private function __board(array $user, array $profile, $editable)
    {
        $row = $profile['AnalystProfile'];
        $parameters = is_array($row['parameters'])
            ? $row['parameters']
            : array();
        $form = new AnalystProfileFormTool();
        $sources = $this->__sources($user, $parameters);
        $focus = $this->__requestedValue();
        if ($focus !== null) {
            $sources = array_merge($sources,
                $this->__contributionsFor($user, $focus, $row));
        }
        $checked = $form->validate($parameters);
        /*
         * Two different questions, and `view` needs the second one.
         * `editable` is *is this page an editor* — false on `view` by
         * construction, because `view` renders the inputs as what they
         * hold. `may_edit` is *would this reader be allowed to*, which
         * is what decides whether the header offers Edit or offers the
         * fork that stands in for it.
         */
        $mayEdit = $this->AnalystProfile->isEditableByCurrentUser($user, $row);
        return array(
            'profile' => $this->AnalystProfile->summarise($row),
            'editable' => $editable && $mayEdit,
            'may_edit' => $mayEdit,
            'may_share' => !empty($user['Role']['perm_site_admin'])
                && !empty($row['user_id'])
                && $row['user_id'] == $user['id'],
            'sections' => $form->sections($parameters, $sources),
            'groups' => $form->groups(),
            'bands' => $form->bandStrip($parameters),
            'errors' => $checked['errors'],
            'warnings' => $checked['warnings'],
            'legacy' => $form->legacyShapes($parameters),
            'loader_errors' => $this->__loaderErrors(),
            'raw' => json_encode($parameters,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'value' => $focus,
            'value_b64' => $focus === null
                ? null
                : ValueUrlTool::encode($focus),
            /*
             * Which section the page opens on. A `not_counted` entry on
             * a value page links straight to the exclusion that
             * produced it, and landing on the signals table with the
             * answer three clicks away would make that link a gesture.
             */
            'open_section' => $this->__requestedSection(),
            'comparison_limit' => self::COMPARISON_LIMIT,
            'comparison_set' => $this->__comparisonSet($user),
            /*
             * The right-hand pane, and it is the simulator rather than
             * a reading of the stored document: the whole bet of this
             * design is that the consequence of an edit is unavoidable
             * rather than merely available, which it is not if the
             * pane shows what the profile already does.
             *
             * It costs nothing when there is nothing to score — no
             * pinned values and no value arrived with means no
             * context is built at all.
             */
            'bench' => $this->__simulation($user, $row, $parameters),
        );
    }

    /**
     * What each weight produced on one value, so `view` can show the
     * contribution beside the number that caused it.
     *
     * **Both ledgers, because the table holds both.** `review-2026-09
     * -13.md` §D1 moved the lean rows out of `ledger` into
     * `lean_ledger`, and walking only the first left the Signals
     * table blank in the one column that says what a weight did — on
     * `127.0.0.1` for `lifecycle.warninglist`, the heaviest row on
     * that record at `+38`, and on `8.8.8.8` for both lean rows, the
     * `−58` that decides its verdict. That is §G1's defect in the
     * surface §G1's fix did not reach: the simulator was taught to
     * read both ledgers, the palette was not, because each walked the
     * ledger itself.
     *
     * So it walks neither. `ValueVerdictDiffTool::rowsById()` is the
     * one traversal and the bench beside this table already uses it,
     * which is what stops the two panes disagreeing about which rows
     * exist.
     *
     * The lean rows carry their anchored contribution, which is what
     * the bench and the value page render, and the row's own *reads
     * the value* badge is what tells an analyst the sign means
     * something different there.
     *
     * @param array $user
     * @param string $value
     * @param array $row
     * @return array `ledger` and `not_counted`, keyed by signal id
     */
    private function __contributionsFor(array $user, $value, array $row)
    {
        $this->loadModel('ValueIntelligence');
        $engine = new ValueVerdictTool($this->ValueIntelligence);
        $verdict = $engine->verdictFor($user, $value,
            array('profile' => $row));
        $ledger = array();
        foreach (ValueVerdictDiffTool::rowsById($verdict) as $signalRow) {
            if (isset($signalRow['contribution'], $signalRow['id'])) {
                $id = $signalRow['id'];
                $ledger[$id] = ($ledger[$id] ?? 0)
                    + $signalRow['contribution'];
            }
        }
        $notCounted = array();
        foreach ($verdict['not_counted'] as $entry) {
            if (!empty($entry['id'])) {
                $notCounted[$entry['id']] = isset($entry['note'])
                    ? $entry['note']
                    : '';
            }
        }
        return array(
            'ledger' => $ledger,
            'not_counted' => $notCounted,
            'verdict' => $verdict,
        );
    }

    /**
     * The option lists the form tool may not fetch for itself.
     *
     * **Only the keys a map already carries**, plus a picker source for
     * adding one. §4 is explicit that `org_trust` must never render a
     * row per organisation on the instance, and the same restraint
     * applies to what is *sent*: an instance with 900 organisations
     * would put 900 names into a response about four of them.
     *
     * @param array $user
     * @param array $parameters
     * @return array
     */
    private function __sources(array $user, array $parameters)
    {
        return array(
            'attribute_types' => $this->__attributeTypes(),
            'orgs' => $this->__gradedOrgs($parameters),
            'warninglists' => $this->__warninglistNames(),
            'modules' => $this->__moduleCatalogue($user),
            'taxonomies' => $this->__enabledTaxonomies(),
            'galaxies' => $this->__enabledGalaxies(),
        );
    }

    /**
     * The taxonomies this instance uses, for the priority lists.
     *
     * **Enabled only** (D41): `enabled = 0` says the instance does not
     * use this taxonomy, and an editor offering it would be offering to
     * rank something nobody here can tag. A profile that already ranks
     * one which was later disabled keeps its entry — the form marks the
     * row rather than dropping it, which is D23's rule that the editor
     * offers what is implemented and the document keeps what is
     * storable.
     *
     * @return array namespace => namespace
     */
    private function __enabledTaxonomies()
    {
        $this->loadModel('Taxonomy');
        $rows = $this->Taxonomy->find('all', array(
            'conditions' => array('Taxonomy.enabled' => 1),
            'fields' => array('Taxonomy.namespace'),
            'recursive' => -1,
            'order' => array('Taxonomy.namespace ASC'),
        ));
        $out = array();
        foreach ($rows as $row) {
            $namespace = mb_strtolower($row['Taxonomy']['namespace']);
            $out[$namespace] = $namespace;
        }
        return $out;
    }

    /**
     * The galaxies this instance uses, keyed by `type`.
     *
     * `type` rather than name, because that is the string inside every
     * tag and the one a priority list holds; the name is how this
     * instance spells it, and it is what the row shows.
     *
     * @return array type => name
     */
    private function __enabledGalaxies()
    {
        $this->loadModel('Galaxy');
        $rows = $this->Galaxy->find('all', array(
            'conditions' => array('Galaxy.enabled' => 1),
            'fields' => array('Galaxy.type', 'Galaxy.name'),
            'recursive' => -1,
            'order' => array('Galaxy.name ASC'),
        ));
        $out = array();
        foreach ($rows as $row) {
            $type = mb_strtolower($row['Galaxy']['type']);
            $out[$type] = empty($row['Galaxy']['name'])
                ? $type
                : $row['Galaxy']['name'];
        }
        return $out;
    }

    /**
     * @return array
     */
    private function __attributeTypes()
    {
        $this->loadModel('MispAttribute');
        return array_keys($this->MispAttribute->typeDefinitions);
    }

    /**
     * The organisations this profile grades, by uuid, with their names.
     *
     * A graded organisation that is not on this instance keeps its uuid
     * as its label rather than disappearing — a profile written
     * elsewhere is the case import exists for, and dropping the row
     * would lose the grade.
     *
     * @param array $parameters
     * @return array uuid => name
     */
    private function __gradedOrgs(array $parameters)
    {
        $uuids = isset($parameters['reference']['org_trust'])
            && is_array($parameters['reference']['org_trust'])
            ? array_keys($parameters['reference']['org_trust'])
            : array();
        if (empty($uuids)) {
            return array();
        }
        $this->loadModel('Organisation');
        $rows = $this->Organisation->find('all', array(
            'conditions' => array('Organisation.uuid' => $uuids),
            'fields' => array('Organisation.uuid', 'Organisation.name'),
            'recursive' => -1,
        ));
        $out = array();
        foreach ($rows as $organisation) {
            $out[$organisation['Organisation']['uuid']] =
                $organisation['Organisation']['name'];
        }
        return $out;
    }

    /**
     * @return array name => id
     */
    private function __warninglistNames()
    {
        $this->loadModel('Warninglist');
        $rows = $this->Warninglist->find('all', array(
            'fields' => array('Warninglist.id', 'Warninglist.name'),
            'recursive' => -1,
            'order' => array('Warninglist.name ASC'),
        ));
        $out = array();
        foreach ($rows as $list) {
            $out[$list['Warninglist']['name']] =
                (int)$list['Warninglist']['id'];
        }
        return $out;
    }

    /**
     * Every enrichment module this instance knows of, what each accepts,
     * and whether this reader could actually use it.
     *
     * **The whole roster, not the usable part of it**, which is the
     * difference between this and `getEnabledModules()`. That method
     * applies three filters and then throws away which one bit, and the
     * editor needs the difference twice over: to offer only modules a
     * reader can pick, and — for a declaration already in the document,
     * typically one written on another instance and imported here — to
     * say *this instance has it turned off* rather than drop the row or
     * leave it looking fine. A profile whose gaps are invisible is the
     * quiet lie `01-profile.md` §1.3 forbids, and an imported profile is
     * mostly gaps.
     *
     * `accepts` is `mispattributes.input`, which is how a module states
     * the attribute types it can answer about. It is the one fact that
     * makes the declaration editable at all: 146 modules on the dev
     * instance accept 71 distinct types between them, median 3 each, so
     * filtering by it turns a 194-key × 146-option table into a handful
     * of short rows. A module declaring no input is not an enrichment
     * module in any sense this page can use — the import and export
     * families come back on the same endpoint — and is dropped here
     * rather than offered as a row that could never match a type.
     *
     * The modules service is a third party and may be down, or switched
     * off entirely (`Enrichment_services_enable` ships `false`).
     * `reachable` says which, because *the service did not answer* and
     * *the service answered with nothing* must not look the same.
     *
     * @param array $user
     * @return array `reachable`, and `catalogue` as name => facts
     */
    private function __moduleCatalogue(array $user)
    {
        $this->loadModel('Module');
        $all = $this->Module->getModules('Enrichment');
        if (!is_array($all)) {
            return array('reachable' => false, 'catalogue' => array());
        }
        $catalogue = array();
        foreach ($all as $module) {
            if (empty($module['name'])) {
                continue;
            }
            $accepts = empty($module['mispattributes']['input'])
                ? array()
                : array_values($module['mispattributes']['input']);
            if (empty($accepts)) {
                continue;
            }
            /*
             * Absent `module-type` reads as `expansion`, which is what
             * `getEnabledModules()` does with it — stated the same way
             * here so the editor and the tab cannot disagree about
             * which modules are in the family.
             */
            $kinds = isset($module['meta']['module-type'])
                && is_array($module['meta']['module-type'])
                ? array_values(array_intersect(
                    $module['meta']['module-type'],
                    array('hover', 'expansion')
                ))
                : array('expansion');
            if (empty($kinds)) {
                continue;
            }
            $name = $module['name'];
            $enabled = (bool)Configure::read(
                'Plugin.Enrichment_' . $name . '_enabled'
            );
            $restricted = !$this->Module->canUse(
                $user,
                'Enrichment',
                $module
            );
            /*
             * A module's own one-line description. Carried because the
             * editor is a list of names otherwise, and `ipasn`,
             * `mmdb_lookup` and `circl_passivedns` are not
             * self-describing to anybody who has not read
             * misp-modules.
             */
            $declared = isset($module['meta']['config'])
                && is_array($module['meta']['config'])
                ? $module['meta']['config']
                : array();
            $catalogue[$name] = array(
                'accepts' => $accepts,
                'kinds' => $kinds,
                'enabled' => $enabled,
                'restricted' => $restricted,
                'description' => $this->__moduleBlurb(
                    isset($module['meta']['description'])
                        ? $module['meta']['description']
                        : ''
                ),
                /*
                 * Enabled and unconfigured is the quietest failure
                 * here — the row looks healthy and the run errors —
                 * so it is read once, where every other instance fact
                 * about a module is read. `ModuleCredentials` decides
                 * which settings are *required*, because introspection
                 * does not say and the obvious guess would warn about
                 * `mmdb_lookup`, which works unconfigured.
                 */
                'unset_required' => $enabled
                    ? ModuleCredentials::unsetFor($name, $declared)
                    : array(),
            );
        }
        ksort($catalogue);
        return array('reachable' => true, 'catalogue' => $catalogue);
    }

    /**
     * A module's own description, cut down to one line under a name.
     *
     * The raw field is a developer's README sentence: a median of 53
     * characters, a maximum of **379**, seven of them carrying a
     * GitHub or project URL, and one opening with a deprecation notice
     * and a blank line. Printed as-is under a table row it is a
     * paragraph where a caption belongs.
     *
     * Cut rather than rewritten — the text is the module author's and
     * editorialising 146 of them is a maintenance burden nobody would
     * keep up. First sentence, whitespace collapsed, a bare
     * parenthesised URL dropped, and a hard cap with an ellipsis so
     * that the one 379-character outlier cannot set the row height for
     * the table.
     *
     * @param string $raw `meta.description`
     * @return string
     */
    private function __moduleBlurb($raw)
    {
        $text = trim(preg_replace('/\s+/', ' ', (string)$raw));
        if ($text === '') {
            return '';
        }
        $text = trim(preg_replace('/\s*\(\s*https?:\/\/[^)]*\)/', '',
            $text));
        /*
         * Capped, not cut to the first sentence. Taking sentence one
         * looked tidier and lost the point: `onion_lookup` opens *MISP
         * module using the MISP standard* and says what it does in the
         * sentence after. The cap is for the 379-character outlier
         * setting the row height, and at a median of 53 it leaves most
         * descriptions alone.
         */
        if (mb_strlen($text) > 150) {
            $text = mb_substr($text, 0, 149) . '…';
        }
        return $text;
    }

    /**
     * The enabled profile of the owner a fork would land on, or null.
     *
     * @param array $user
     * @param bool $forOrg
     * @return array|null
     */
    private function __enabledFor(array $user, $forOrg)
    {
        $conditions = array(
            'AnalystProfile.enabled' => 1,
            'AnalystProfile.shared' => 0,
        );
        if ($forOrg) {
            $conditions['AnalystProfile.org_id'] = $user['org_id'];
        } else {
            $conditions['AnalystProfile.user_id'] = $user['id'];
        }
        $profile = $this->AnalystProfile->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        return empty($profile) ? null : $profile['AnalystProfile'];
    }

    /**
     * How many colleagues an organisation profile would apply to.
     *
     * Under D3 an org profile is what every colleague who has not
     * forked resolves to, so this counts the users in the organisation
     * who hold no enabled profile of their own — which is the number the
     * confirm has to name (§6). Counting the whole organisation would
     * overstate it and counting nobody would understate it.
     *
     * @param array $user
     * @return array
     */
    private function __orgReaders(array $user)
    {
        $this->loadModel('User');
        $total = $this->User->find('count', array(
            'conditions' => array(
                'User.org_id' => $user['org_id'],
                'User.disabled' => 0,
            ),
            'recursive' => -1,
        ));
        $owners = $this->AnalystProfile->find('all', array(
            'conditions' => array(
                'AnalystProfile.enabled' => 1,
                'AnalystProfile.shared' => 0,
                'AnalystProfile.user_id !=' => null,
            ),
            'fields' => array('AnalystProfile.user_id'),
            'recursive' => -1,
        ));
        $ownerIds = array();
        foreach ($owners as $owner) {
            $ownerIds[] = (int)$owner['AnalystProfile']['user_id'];
        }
        $exempt = 0;
        if (!empty($ownerIds)) {
            $exempt = $this->User->find('count', array(
                'conditions' => array(
                    'User.org_id' => $user['org_id'],
                    'User.disabled' => 0,
                    'User.id' => $ownerIds,
                ),
                'recursive' => -1,
            ));
        }
        return array(
            'users' => (int)$total,
            'own_profile' => (int)$exempt,
            'affected' => max(0, (int)$total - (int)$exempt),
        );
    }

    /**
     * The profile or a 404 — never "you may not see this", which would
     * confirm that a profile with that id exists.
     *
     * @param array $user
     * @param int|string|null $id
     * @return array
     * @throws NotFoundException
     */
    private function __profileOr404(array $user, $id)
    {
        if ($id === null || $id === '') {
            throw new NotFoundException(__('No profile named.'));
        }
        $profile = $this->AnalystProfile->fetchProfile($user, $id);
        if (empty($profile)) {
            throw new NotFoundException(__('Invalid analyst profile.'));
        }
        return $profile;
    }

    /**
     * The exportable document: what an import expects to be handed.
     *
     * @param array $row
     * @return array
     */
    private function __document(array $row)
    {
        return array(
            'uuid' => $row['uuid'],
            'name' => $row['name'],
            'description' => $row['description'],
            'version' => (int)$row['version'],
            'parameters' => is_array($row['parameters'])
                ? $row['parameters']
                : array(),
        );
    }

    /**
     * Files the loader skipped, both subjects at once.
     *
     * The engine skips them silently (03-signals.md §8.5), so this is
     * the page where an admin finds out — `Workflow` surfaces
     * `$error_while_loading` in the same place for the same reason.
     *
     * @return array
     */
    private function __loaderErrors()
    {
        $errors = array();
        foreach (array(
            ValueSignalLoader::SUBJECT_SIGNAL => __('Signal'),
            ValueSignalLoader::SUBJECT_ESCALATION => __('Escalation'),
        ) as $subject => $label) {
            foreach (ValueSignalLoader::errors($subject) as $file => $why) {
                $errors[] = array(
                    'subject' => $label,
                    'file' => $file,
                    'reason' => $why,
                );
            }
        }
        return $errors;
    }

    /**
     * A document in a comparable form — recursively key-sorted, so two
     * documents differing only in key order compare equal.
     *
     * This is what decides whether `revision` moves. A form that
     * round-trips a section can reorder its keys without changing a
     * single value, and a revision bumped for that would invalidate
     * every materialised assessment phase 10 stores for nothing.
     *
     * @param mixed $value
     * @return string
     */
    private function __canonical($value)
    {
        return json_encode($this->__sortKeys($value));
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function __sortKeys($value)
    {
        if (!is_array($value)) {
            return $value;
        }
        $out = array();
        foreach ($value as $key => $member) {
            $out[$key] = $this->__sortKeys($member);
        }
        ksort($out);
        return $out;
    }

    /**
     * CakePHP's per-field error map as a flat list of sentences.
     *
     * @param array $errors
     * @return array
     */
    private function __flatten(array $errors)
    {
        $out = array();
        foreach ($errors as $field => $messages) {
            foreach ((array)$messages as $message) {
                $out[] = is_string($field) && !is_numeric($field)
                    ? sprintf('%s: %s', $field, $message)
                    : $message;
            }
        }
        return $out;
    }

    /**
     * A refusal, with everything the reader needs to fix it.
     *
     * **Through MISP's own failure helper, and it answers 403.** The
     * first implementation set 400 on `$this->response` and handed the
     * body to `viewData()` — which ignores it: `prepareResponse()`
     * builds a fresh `CakeResponse` with the code it was passed, and
     * `viewData()` always passes 200. So every refusal answered *200
     * with `saved: false`*, which tells an automated caller the save
     * happened and leaves the truth in the body.
     *
     * 403 is semantically odd for a validation failure, and it is what
     * `saveFailResponse()` has answered for every failed save in MISP
     * for years. Consistency with the platform wins over REST purity
     * here: a client that already treats 403-with-`saved: false` as a
     * refused save handles this endpoint with no special case.
     *
     * **A browser is refused on the page it posted from**, with the
     * document it posted still in the form. Redirecting to the index
     * would answer *"no"* and throw away the paste that caused it,
     * which is the one thing an analyst cannot get back.
     *
     * @param array $errors
     * @param array $extra Carried under `data`, which is where the
     *                     helper puts a caller's own payload
     * @param array|null $html `view` and `vars` — the page to re-render
     *                         for a browser, with what it should show
     * @return CakeResponse
     */
    private function __refuse(array $errors, array $extra = array(),
        array $html = null
    ) {
        if (!$this->_isRest()) {
            foreach ($errors as $error) {
                $this->Flash->error($error);
            }
            if ($html === null) {
                return $this->redirect(array('action' => 'index'));
            }
            if (isset($html['redirect'])) {
                return $this->redirect($html['redirect']);
            }
            $vars = $html['vars'];
            $vars['errors'] = array_merge(
                isset($vars['errors']) ? $vars['errors'] : array(),
                $errors
            );
            $this->set($vars);
            $this->set('payload', $vars);
            return $this->render($html['view']);
        }
        return $this->RestResponse->saveFailResponse(
            'AnalystProfiles',
            isset($this->request->params['action'])
                ? $this->request->params['action']
                : 'edit',
            isset($this->request->params['pass'][0])
                ? $this->request->params['pass'][0]
                : false,
            $errors,
            'json',
            empty($extra) ? null : $extra
        );
    }

    /**
     * Every action's answer, in whichever of the two shapes the caller
     * asked for.
     *
     * **The same array, both ways.** A REST caller gets exactly the
     * JSON it got before there were templates; a browser gets the
     * template, handed the identical keys. An action that grew a
     * second view-model for its page would put the fixtures and the
     * page out of step the first time one of them changed, and the
     * fixtures are what the templates are checked against.
     *
     * An action with no view — every write — is JSON either way, and
     * the HTML path is `__wrote()` below.
     *
     * @param array $data
     * @param string|null $view
     * @return CakeResponse
     */
    private function __payload(array $data, $view = null)
    {
        if ($view === null || $this->_isRest()) {
            return $this->RestResponse->viewData($data, 'application/json');
        }
        $this->set($data);
        $this->set('payload', $data);
        return $this->render($view);
    }

    /**
     * A write's answer: the payload over REST, a flash and a redirect
     * in a browser.
     *
     * A write has nothing to render — the page a reader wants next is
     * the one showing the result — so the outcome travels as a flash
     * and the destination is named by the caller rather than guessed
     * from the referer, which lies as soon as a confirm sat in between.
     *
     * @param array $data
     * @param string $message
     * @param array|string $url
     * @return CakeResponse
     */
    private function __wrote(array $data, $message, $url)
    {
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, 'application/json');
        }
        $this->Flash->success($message);
        return $this->redirect($url);
    }

    /**
     * A write that stopped to ask.
     *
     * The two that do are the one-enabled swap and a fork into an
     * occupied slot, and both are refusals to act silently rather than
     * failures: the consequence is named, and the same POST carrying
     * `replace` goes through. REST callers get the same payload and
     * decide for themselves.
     *
     * @param array $data
     * @param array $form `url`, `fields` and `confirm_label`
     * @return CakeResponse
     */
    private function __confirm(array $data, array $form)
    {
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, 'application/json');
        }
        $this->set($data);
        $this->set('form', $form);
        return $this->render('confirm');
    }
}
