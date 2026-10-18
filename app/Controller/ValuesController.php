<?php
App::uses('AppController', 'Controller');
App::uses('MispTheme', 'MispTheme');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ValueInputTool', 'Tools/ValueIntelligence');
App::uses('ValueConditionRewriter', 'Tools');
App::uses('Value', 'Model');

/**
 * Value Intelligence controller, mounted at /values/* via CakePHP's default
 * routing.
 *
 * The subject of these pages is a value string — an IP address, a hash,
 * a domain — not a single attribute row. The same value exists as many
 * attribute rows across many events, and this controller aggregates them.
 *
 * Read-only: nothing here writes. Each panel is its own lazily loaded
 * endpoint, answered by one `ValueIntelligence` method.
 *
 * **One action leaves the building**, and it is the only one:
 * `viewEnrichmentRun` queries a third-party module. It still writes
 * nothing to MISP — see its docblock for what that costs instead, and
 * why it is the page's only POST.
 *
 * As JSON, `view`, `search` and `delete` are the value dictionary's API:
 * a stored value and the attributes holding it that the user can see.
 *
 * @property AttributeValue $AttributeValue
 * @property MispAttribute $MispAttribute
 */
class ValuesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    // The dictionary API's model; the panels load their own as they land.
    public $uses = array('AttributeValue');

    /**
     * Where every element this controller renders lives, and the only
     * place any of them lives: `View/Themed/Overmind/Elements/Values`.
     * There is no unthemed fallback to fall back to.
     */
    const THEME = 'Overmind';

    const LIMIT = 60;

    const MAX_LIMIT = 1000;

    const MAX_PAGE = 1000000;

    const SEARCH_MODES = ['search', 'like', 'exact'];

    /**
     * A panel is an HTML fragment and has no other representation.
     *
     * `Router::parseExtensions` accepts `json`, `xml` and `csv` on every
     * route, so any of them could be appended to a panel URL — and
     * `RequestHandler` also infers one from an `Accept` header. What
     * came back was a 500: the extension makes `AppController` treat
     * the request as REST, REST skips the block that sets the theme,
     * and a themeless render cannot find an element that exists only
     * under a theme. Every panel threw `MissingViewException`.
     *
     * Refusing is the honest answer rather than serving something. A
     * panel is markup built for one page to inject; there is no JSON
     * shape of it to define, and `live/00-contract.md` §14.11 puts an
     * API for this page out of scope.
     *
     * @return void
     * @throws NotFoundException
     */
    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->__unnameSha256();
        $json = in_array(
            $this->request->params['action'] ?? null,
            array('graph', 'graphOccurrences', 'enrichmentTypes',
                'enrichmentStored', 'enrichmentRun', 'view', 'search',
                'delete'),
            true
        );
        if (!$json) {
            $this->__rejectNonHtmlExtension(
                $this->request->params['ext'] ?? null
            );
        }
        $this->_csrfTokenHeaderOnly(array('graphOccurrences',
            'enrichmentStored', 'enrichmentRun'));
        /*
         * The run endpoint posts two scalars and no form, so the
         * form-tampering hash has nothing to check and its absence
         * would blackhole every run. The CSRF check stays on —
         * `viewEnrichmentRun` says why that half is worth keeping
         * where MISP's usual ajax treatment drops both.
         *
         * **`triage` is the prompt's own form posted somewhere else.**
         * `FormHelper` hashes the field list together with the form's
         * action, and `SecurityComponent` checks that hash against the
         * URL the request arrived at — so the one form on this page,
         * built for `resolve` and sent by the page's script to
         * `triage` instead, fails a check that nothing is wrong with.
         * Emitting a second form for the same textarea to satisfy it
         * would put two copies of the reader's paste in the document.
         * What the hash protects is a field set the reader is not
         * meant to choose, and this form's field set is one textarea
         * they type into: there is nothing here to tamper with that
         * tampering would gain. CSRF is the half that matters and it
         * stays on.
         */
        if (in_array(
            $this->request->params['action'] ?? null,
            array('viewEnrichmentRun', 'viewEnrichmentBadge', 'triage',
                'assess', 'matches'),
            true
        )) {
            $this->Security->validatePost = false;
        }

        /*
         * **A use-once CSRF token cannot survive this page.**
         *
         * `SecurityComponent::generateToken()` is a read-modify-write
         * on one session key: it reads `_Token.csrfTokens`, adds the
         * nonce it just minted, and writes the map back. This page
         * loads its panels lazily and in parallel — around twenty
         * requests land together — so two that overlap both read the
         * same map and the later write drops the earlier one's nonce.
         * Whichever request the Enrichment panel was is as likely as
         * any other to be the one dropped, and the run it embedded a
         * token for then blackholes at 400.
         *
         * Measured before this line existed: **two of five** browser
         * runs failed that way, against six of six over plain HTTP,
         * where nothing is concurrent. That gap is the whole tell —
         * the defect is in the page's concurrency, not the endpoint.
         *
         * A stable per-session token is the fix and not a weakening:
         * it is the synchroniser-token pattern every later CakePHP
         * uses, and CSRF turns on an attacker being unable to *read*
         * the token cross-origin, never on its being fresh. Every
         * concurrent write now writes the same key, so the lost
         * update stops mattering, and a reader can run several
         * modules without each press spending the next one's token.
         *
         * Scoped to this controller, which posts exactly one thing.
         */
        $this->Security->csrfUseOnce = false;
    }

    /**
     * Cake reads `sha256:<hex>` as a named parameter and drops it from the
     * positional ones, which would shift `$galaxyId`, `$from` and `$to`.
     * Every action but the REST `view` takes it back as its first argument.
     *
     * @return void
     */
    private function __unnameSha256()
    {
        $named = $this->request->params['named'] ?? array();
        if (!isset($named['sha256']) || !is_string($named['sha256'])
            || ($this->request->params['action'] === 'view'
                && $this->_isRest())
        ) {
            return;
        }
        array_unshift($this->request->params['pass'],
            ValueUrlTool::SHA256_PREFIX . $named['sha256']);
        unset($this->request->params['named']['sha256']);
    }

    /**
     * The guard above, named so it can be exercised on its own — the
     * filter it runs from needs a session and this does not.
     *
     * @param string|null $extension The route's parsed extension
     * @return void
     * @throws NotFoundException
     */
    protected function __rejectNonHtmlExtension($extension)
    {
        if ($extension === null || $extension === 'html') {
            return;
        }
        throw new NotFoundException(__(
            'The Value Intelligence panels are HTML fragments and have no'
            . ' %s representation.',
            strtoupper($extension)
        ));
    }

    /**
     * Render under the theme the panels live in, whoever is asking.
     *
     * `AppController` sets a theme only for a non-REST request, so a
     * REST call reaches `render()` with none, and every panel would
     * throw `MissingViewException`. This page has one implementation
     * and it is under `Overmind`, so naming it here is a statement of
     * where the files are rather than a preference overriding the
     * reader's.
     *
     * A theme the user did choose is left alone **only if it carries
     * these views**. It is a floor, not a ceiling — but the first
     * version tested for *no theme at all*, and an analyst whose
     * `ui_theme` is `Default` has a theme, so the floor never fired
     * and every one of them got a 500 instead of a value page.
     *
     * @return void
     */
    public function beforeRender()
    {
        parent::beforeRender();
        if (!MispTheme::carries($this->theme, 'Values')) {
            $this->theme = self::THEME;
            $this->viewClass = 'Theme';
        }
    }

    /**
     * The way in: one box, and what it resolved.
     *
     * Not a CakePHP index and it cannot be one. `Value::$useTable` is
     * false because the subject of this feature is a string rather
     * than a row, so *all values* is a `GROUP BY value1` over 3.9M
     * attribute rows that no `LIMIT` bounds — `value-index.md` §1.1.
     * Everything this page draws is therefore either supplied by the
     * caller or read from a table that is genuinely value-keyed.
     *
     * On a `GET` there is no answer to set, so the page is the
     * prompt and the invitation that says what pressing it does.
     *
     * @return void
     */
    public function index()
    {
        return $this->__indexPage(null, null);
    }

    /**
     * The index page, whatever brought the reader to it.
     *
     * `resolve()` renders this view from four places and `index()`
     * from a fifth, and every one of them owes the template the same
     * variables. A block added to the page is otherwise a block added
     * to five call sites, four of which a reviewer reads as unrelated
     * — and phase 3 has already been bitten once by something that
     * rendered, and rendered wrong, rather than failing. Phase 6's
     * carried-over list was the first of the small blocks to arrive
     * through here, phase 7's profile the second and phase 9's tile row
     * the third; phase 8 needed nothing, because a method note has no
     * data to be given.
     *
     * @param array|null $resolution What `resolve()` made of the box
     * @param array|null $triage The rows a pasted list became
     * @return CakeResponse
     */
    private function __indexPage($resolution, $triage)
    {
        $this->loadModel('ValueIntelligence');
        $user = $this->Auth->user();
        $this->set('resolution', $resolution);
        $this->set('triage', $triage);
        $this->set('recent', $this->ValueIntelligence->forRecent($user));
        $this->set(
            'inForce',
            $this->ValueIntelligence->forProfileInForce($user)
        );
        $this->set('tiles', $this->ValueIntelligence->forTiles($user));
        $this->set('showsAssessment', $this->__showsAssessment());
        return $this->render('index');
    }

    /**
     * One value, resolved: the profile, or the honest answer that
     * nothing here records it.
     *
     * **A POST, and the value is in the body** (§8 G2). A `GET` would
     * put the reader's indicator in browser history, in the access
     * log, and in the `Referer` of everything the next page loads —
     * the disclosure `D27` refuses elsewhere, arriving through the web
     * server instead of through the page. The cost is that a
     * resolution cannot be bookmarked; `/values/view/<b64>` can, and
     * that is the link this action hands over.
     *
     * **A value with nothing recorded is not a 404.** A reader who
     * pasted a hash to find out whether anyone has seen it has had
     * their question answered by the answer *no*, and the profile's
     * own empty state says the same thing with the tabs to prove it.
     * `__decodeValue`'s `NotFoundException` is right for a malformed
     * URL and wrong for this.
     *
     * **The parser's count routes, not the line count.** One value is
     * a profile and more than one is the worklist, which phase 4 put
     * behind this same box. Phase 3 routed on lines instead, because
     * with no worklist to route to a comma could only be part of a
     * value; now that there is one, `1.2.3.4, 5.6.7.8` typed on one
     * line has to become two rows, and `example.com|1.2.3.4` has to
     * become two as well — the composite resolves to nothing as a
     * string, since `value1` and `value2` hold its halves and no
     * column holds the pair.
     *
     * What that costs is the one reader whose value legitimately
     * contains a comma, and they are not lost: the worklist says the
     * commas split their line and offers the whole line as one value,
     * which arrives back here as `whole` and is the only caller of
     * `normalise()` left. An offer rather than a rule, for the reason
     * the did-you-mean is one — only the reader knows which their
     * report meant.
     *
     * @return void
     */
    public function resolve()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $raw = $this->__pasted();
        if (!empty($this->request->data['Value']['whole'])) {
            /*
             * The worklist's offer, come back: the line the commas
             * split, taken whole. `normalise()` splits nothing, which
             * is what makes a value carrying a separator reachable at
             * all (§3.1).
             */
            $one = ValueInputTool::normalise($raw);
        } else {
            $many = $this->__parse($raw);
            $report = $many['report'];
            if ($report['overflow'] > 0) {
                return $this->__indexPage(
                    $this->__refusal($report),
                    null
                );
            }
            /*
             * **An extraction always lands on the worklist**, even on
             * one value, where a list reading would redirect to the
             * profile. A reader who asked the page to find the values
             * in their report is owed the count it found as well as
             * the value — *one* is an answer about their report — and
             * the paste they are still reading stays on screen. It is
             * also what keeps the scripted road and the no-script road
             * giving the same answer, since the script sends every
             * extraction to `triage()`.
             */
            if (count($many['values']) > 1
                || ($this->__extracting() && $many['values'])
            ) {
                return $this->__indexPage(
                    null,
                    $this->__triage($many)
                );
            }
            /*
             * One value left, whatever the paste looked like getting
             * there — the same indicator twice, or a value beside its
             * own defanged spelling. The report describes that value,
             * so its counts read back as the tokens `normalise()`
             * would have returned.
             */
            $one = array(
                'value' => isset($many['values'][0])
                    ? $many['values'][0]
                    : null,
                'changed' => $this->__changedIn($report),
            );
        }
        if ($one['value'] === null) {
            return $this->__indexPage($this->__nothing(), null);
        }
        $this->loadModel('ValueIntelligence');
        $answer = $this->ValueIntelligence->forResolve(
            $this->Auth->user(),
            $one['value']
        );
        if ($answer['recorded']) {
            /*
             * **The instance's spelling, not the reader's.** The value
             * columns are case-insensitive and MISP lowercases hashes,
             * domains, hostnames and email addresses on the way in, so
             * `CiRcL.lu` matches rows that all say `circl.lu` — and
             * `view()` renders whatever string its URL carries. Sent
             * the reader's own, the profile would be titled with a
             * value nobody holds over the occurrences of one
             * everybody does.
             */
            $this->__sayWhatChanged($one, $answer['stored']);
            return $this->redirect(
                array('action' => 'view', ValueUrlTool::address(
                    $answer['stored']
                )),
                303
            );
        }
        return $this->__indexPage(array(
            'kind' => 'absent',
            'value' => $one['value'],
            'changed' => $one['changed'],
            'suggestion' => $answer['suggestion'],
        ), null);
    }

    /**
     * A pasted list, as the rows to work — **the fragment alone**.
     *
     * The block the page replaces when the reader presses with more
     * than one value in the box, which is why it renders an element
     * and not a page: the paste stays in the textarea above it
     * untouched, the reader keeps their scroll position, and phase 5
     * has a block it can refill without a navigation. The page still
     * works with no script at all — `resolve()` routes a list to the
     * same builder and renders the whole page around it.
     *
     * **No assessment here** (§7.2). This phase parses: it cleans the
     * list, splits composites, drops duplicates, canonicalises each
     * value's spelling and links it. A row that said *recorded* or
     * *not recorded* would be a row that looks different for a value
     * the reader may not see, which is the identity §4.2 holds.
     *
     * **A one-value paste is a one-row list, not an error.** The page
     * script counts the reader's paste with a cruder parser than this
     * one and can be one out — a defanged spelling and its fanged
     * twin are one value here and two there — so this endpoint is
     * reachable with a single value, and a list of one that links to
     * a profile is a perfectly good answer to give.
     *
     * @return void
     */
    public function triage()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $many = $this->__parse($this->__pasted());
        $report = $many['report'];
        $this->layout = false;
        if ($report['overflow'] > 0) {
            $this->set('resolution', $this->__refusal($report));
            return $this->render('/Elements/Values/Index/answer');
        }
        if (empty($many['values'])) {
            $this->set('resolution', $this->__nothing($report));
            return $this->render('/Elements/Values/Index/answer');
        }
        $this->set('triage', $this->__triage($many));
        $this->set('showsAssessment', $this->__showsAssessment());
        return $this->render('/Elements/Values/Index/worklist');
    }

    /**
     * One row of the worklist, assessed.
     *
     * **A POST carrying one value, and the reason it is not the hover
     * card's GET** (`02a-contract.md` §12.4). `viewHoverCard` already
     * exists, is already ACL'd and already returns exactly this
     * assessment — taking it as-is was the cheapest way to fill these
     * rows, and it would have put the reader's whole IOC list through
     * the access log one line at a time. That the hover card leaks the
     * same value elsewhere is true and is not the same quantity: a
     * hundred deliberate hovers over an hour is a different act from
     * one keypress producing a hundred logged lookups, and *the
     * reader's list, one line each* is a fair description of the
     * resulting log. The fix is this route and no engine change.
     *
     * **One request per value, five lanes**, which is the transport
     * all three prototypes proposed and the pick took. It costs N
     * round trips rather than one, and it buys: the first answers in
     * about 10 ms instead of the last in 1.2 s, no request held open
     * for the length of a hundred assessments, and a lane that fails
     * failing one row rather than the batch. The page draws every one
     * of those states.
     *
     * **The value arrives as the worklist spelled it** — the stored
     * spelling where the instance holds one, the reader's own where it
     * does not — and is not parsed again. `ValueInputTool` already
     * produced this string, and re-running it here would let a second
     * parse of an already-parsed value disagree with the link in the
     * same row.
     *
     * **Nothing is enriched** (§8 G7). `forHoverCard` reads the
     * record; asking a module is `viewEnrichmentRun`, a press, and a
     * triage of a hundred values that quietly made a hundred outbound
     * calls would be a denial-of-service vector wearing a paste box.
     *
     * @return void
     */
    public function assess()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        /*
         * Five of these land together, so the same insurance
         * `viewEnrichmentRun` carries applies: a session handler
         * holding an exclusive lock would serialise the lanes and the
         * fifth answer would arrive after the sum of the first four —
         * a failure that looks exactly like a slow instance.
         */
        $this->_closeSession(true);
        $value = trim($this->__pasted());
        if ($value === '') {
            throw new BadRequestException(__('No value supplied.'));
        }
        $this->loadModel('ValueIntelligence');
        $this->set('assessment', $this->ValueIntelligence->forHoverCard(
            $this->Auth->user(),
            $value
        ));
        $this->layout = false;
        return $this->render('/Elements/Values/Index/assessment');
    }

    /**
     * The stored values the box's text matches, one page of them, for the
     * worklist to draw — text only, never a dictionary id.
     *
     * A POST like the rest of the page, so the search text stays out of
     * URLs and logs; `page` rides in the body beside it.
     *
     * @return CakeResponse
     */
    public function matches()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $this->loadModel('ValueIntelligence');
        $page = filter_var(
            $this->request->data['Value']['page'] ?? 1,
            FILTER_VALIDATE_INT,
            array('options' => array('min_range' => 1, 'max_range' => self::MAX_PAGE))
        );
        if ($page === false) {
            throw new BadRequestException(__('Invalid page.'));
        }
        $matches = $this->ValueIntelligence->forMatches(
            $this->Auth->user(),
            $this->__pasted(),
            $page,
            !empty($this->request->data['Value']['anywhere'])
        );
        return $this->RestResponse->viewData($matches, 'json');
    }

    /**
     * What was in the box.
     *
     * @return string
     */
    private function __pasted()
    {
        return isset($this->request->data['Value']['value'])
            ? (string)$this->request->data['Value']['value']
            : '';
    }

    /**
     * Which reading of the box the reader asked for.
     *
     * One checkbox, sent with the paste, and **nothing remembers it**
     * (`value-index.md` §11, V20). Only the reader knows whether they
     * pasted a list of values or a report with values in it, and a
     * remembered answer is the page deciding on their behalf for the
     * next paste, which will be the other kind.
     *
     * @return bool
     */
    private function __extracting()
    {
        return !empty($this->request->data['Value']['extract']);
    }

    /**
     * The box, as values — whichever reading was asked for.
     *
     * Both roads land on the same `['values', 'report']` pair with the
     * same keys, so nothing downstream of here learns a second shape:
     * `__triage()`, the refusal and the worklist each read one report.
     *
     * @param string $raw
     * @return array{values: array<string>, report: array}
     */
    private function __parse($raw)
    {
        return $this->__extracting()
            ? ValueInputTool::extractMany($raw)
            : ValueInputTool::normaliseMany($raw);
    }

    /**
     * Over the cap: the count, and nothing read.
     *
     * **Refused, never truncated** (§7.2). A page that quietly
     * assessed the first hundred of three hundred and forty would
     * have answered a question the reader did not ask, and the two
     * hundred and forty it dropped are the ones they would never
     * think to check. The count is the *input's* — `normaliseMany`
     * counts what was pasted rather than what it returned, so the
     * number the refusal names is the number the reader can act on.
     *
     * Nothing is read here: the refusal happens on the parse, before
     * any model is loaded, so an oversized paste costs the instance a
     * `preg_split` and no statement at all.
     *
     * @param array $report A `ValueInputTool::normaliseMany` report
     * @return array
     */
    /**
     * The box gave nothing, and which reading gave nothing.
     *
     * An empty box and a page of prose the extractor found no
     * indicator in are the same shape and not the same answer: the
     * first is *you pasted nothing*, the second is *this found nothing
     * in what you pasted*, and only the second is worth offering a way
     * back from. The element draws them apart on `mode` alone.
     *
     * @param array|null $report The parser's report, where there was one
     * @return array
     */
    private function __nothing(?array $report = null)
    {
        return array(
            'kind' => 'empty',
            'mode' => $report === null
                ? ($this->__extracting()
                    ? ValueInputTool::MODE_EXTRACT
                    : ValueInputTool::MODE_LINES)
                : $report['mode'],
            'lines' => $report === null ? 0 : $report['lines'],
        );
    }

    private function __refusal(array $report)
    {
        return array(
            'kind' => 'over',
            'count' => $report['total'],
            'cap' => $report['cap'],
            'goes' => (int)ceil($report['total'] / max(1, $report['cap'])),
        );
    }

    /**
     * The rows, and what the parse did to get to them.
     *
     * @param array $many A `ValueInputTool::normaliseMany` answer
     * @return array `rows`, `report`, and the two counts the spelling
     *               read adds to it
     */
    private function __triage(array $many)
    {
        $this->loadModel('ValueIntelligence');
        $triage = $this->ValueIntelligence->forTriage(
            $this->Auth->user(),
            $many['values']
        );
        $triage['report'] = $many['report'];
        return $triage;
    }

    /**
     * Carry the parse across the redirect, when it altered the value.
     *
     * A flash rather than a query parameter: the whole point of §8 G2
     * is that the value does not travel in a URL, and `?refanged=…`
     * would carry both spellings of it into the log the POST exists to
     * keep them out of.
     *
     * **It names the value and not the paste.** The reader is about
     * to lose sight of the box, so what they need carried across is
     * the string the profile is about; the string they typed is the
     * one they still remember, and quoting a defanged spelling back
     * at them puts it in the session store for no gain.
     *
     * **Only the parse is worth saying.** A refang and a quote strip
     * change the string outright, so a reader who is not told has no
     * way to tell either from a wrong answer. A value that differed
     * from the stored spelling only in case says so by arriving: the
     * banner on the profile is the spelling, in the size the page
     * gives it, and a toast repeating it is one more thing to dismiss.
     *
     * @param array $one What `ValueInputTool::normalise` made of it
     * @param string $stored How the instance spells it — what the
     *                       reader is landing on, so what is named
     * @return void
     */
    private function __sayWhatChanged(array $one, $stored)
    {
        $changed = $one['changed'];
        if (in_array(ValueInputTool::REFANGED, $changed, true)) {
            $said = __('Values are stored refanged, so your paste'
                . ' resolved to %s.');
        } elseif (in_array(ValueInputTool::UNQUOTED, $changed, true)) {
            $said = __('Quotes are not part of a value, so your paste'
                . ' resolved to %s.');
        } else {
            return;
        }
        $this->Flash->info(sprintf($said, $stored));
    }

    /**
     * Which transformations a one-value parse report describes.
     *
     * `normaliseMany` counts the input rather than listing what each
     * value carried, which is the right shape for a table of a
     * hundred rows and the wrong one here. With a single value left
     * the counts are that value's, so they read back as tokens — the
     * same tokens `normalise()` returns, so the caller cannot tell
     * which of the two parsed.
     *
     * @param array $report A `ValueInputTool::normaliseMany` report
     * @return array<string>
     */
    private function __changedIn(array $report)
    {
        $changed = array();
        foreach (
            array(ValueInputTool::UNQUOTED, ValueInputTool::REFANGED)
            as $token
        ) {
            if (!empty($report[$token])) {
                $changed[] = $token;
            }
        }
        return $changed;
    }

    /**
     * The full profile page for one value: what `view` renders for a
     * browser.
     *
     * @param string $b64value
     * @return void
     * @throws ForbiddenException
     */
    private function __valuePage($b64value)
    {
        /*
         * The frame, live since phase 29 — the banner's type and
         * warninglist chips, the `value2` note, the fact strip and the
         * tab badges, in one read. It is the only synchronous read on
         * this page and `ValueIntelligence::forFrame` carries its budget.
         */
        $this->loadModel('ValueIntelligence');
        $profile = $this->ValueIntelligence->forFrame(
            $this->Auth->user(),
            $this->__decodeValue($b64value)
        );
        /*
         * And the Assessment tab's pill, for the same reason and at a
         * higher price. It names a lean and a signal strength, and the tab
         * below it computes both: a pill that did not would contradict
         * the body under it.
         *
         * This is the one synchronous assessment on the page. The three
         * lazy endpoints each compute their own (§2 of `10-wiring.md`
         * on why there is nothing to share between processes), so the
         * page pays a fourth to put a word in the tab bar — which is
         * the honest price of a badge that cannot be caught lying, and
         * it is measured on the conversion board rather than assumed.
         */
        $profile['verdict'] = $this->__showsAssessment()
            ? $this->__verdictFor($b64value)['verdict']
            : null;
        $this->set('valueIntelligence', $profile);
        // Re-encoded rather than passed through, so the panel URLs the page
        // builds are well-formed whichever alphabet the caller arrived with.
        $this->set('valueB64', ValueUrlTool::address($profile['value']));
        $this->__setOrgGrading();
        /*
         * And the one write this page makes: `/values/index` carries
         * the last ten values a reader opened, so opening one is what
         * puts it there (`value-index.md` §7.4). It goes last because
         * it is a convenience and the profile is the page — a list
         * that could not be written must not cost anybody a value.
         *
         * The string recorded is the one the URL carried, which is the
         * instance's own spelling for every reader who arrived through
         * the resolver, because that is the value it redirects to.
         */
        $this->ValueIntelligence->rememberViewed(
            $this->Auth->user(),
            $profile['value']
        );
    }

    /**
     * The panels, one lazily-loaded fragment each.
     *
     * A panel per endpoint rather than one endpoint per page: each is a
     * different question of a different model, they answer at different
     * speeds, and a slow one should not hold up the rest. It also means
     * each panel's live implementation is one action and one element.
     *
     * @param string $b64value
     * @return void
     */
    public function viewOccurrences($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forOccurrences',
            'value_occurrences'
        );
    }

    /**
     * The Overview's reporting card — who put the value here, and when.
     *
     * The two summaries phase 31 brought onto this tab from the two
     * that already carried them: the organisation split is the
     * occurrence half of the Assessment tab's *Who says what*, the
     * month strip is the Timeline tab's *Activity on this value*, and
     * `ValueIntelligence::forReporting` reads both through the same methods
     * those tabs read so the three cannot disagree.
     *
     * @param string $b64value
     * @return void
     */
    public function viewReporting($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forReporting',
            'value_reporting'
        );
    }

    public function viewContext($b64value = null)
    {
        $this->__renderLivePanel($b64value, 'forContext', 'value_context');
    }

    /**
     * The Overview's preview of the Collaboration tab.
     *
     * It reads the tab's own union rather than a cheaper one of its
     * own — `ValueIntelligence::forAnalystPreview` has the argument.
     *
     * @param string $b64value
     * @return void
     */
    public function viewAnalystPreview($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forAnalystPreview',
            'value_analyst_preview'
        );
    }

    /**
     * The Overview's verdict card.
     *
     * Live since phase 9, and it computes the assessment itself rather
     * than reading one the tab left behind: the two are separate lazy
     * requests and they agree because `assess()` is deterministic, not
     * because either can see the other. `ValueIntelligence::forVerdict` says
     * why that is the only guarantee available here.
     *
     * @param string $b64value
     * @return void
     */
    public function viewVerdictCard($b64value = null)
    {
        $this->__renderPanel(
            $this->__verdictFor($b64value),
            'value_verdict_card'
        );
    }

    /**
     * The hover card, for a reader who has not opened this page.
     *
     * The only endpoint here that is fetched from somewhere else:
     * every other action answers the Value Intelligence's own lazy panels,
     * and this one answers an attribute row on an event page, an index
     * table, or an object card. It is a fragment like the rest and
     * arrives through the same `X-Requested-With` path.
     *
     * **It is served from this controller and not from wherever the
     * reader is**, which is what lets `beforeRender()` put it under
     * Overmind whatever theme the host page is drawn in, and what
     * keeps one assessment in one place. `ValueIntelligence::forHoverCard`
     * carries the cost argument.
     *
     * @param string $b64value
     * @return void
     */
    public function viewHoverCard($b64value = null)
    {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->forHoverCard(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            'value_hover_card'
        );
    }

    /**
     * The Overview's sightings card, and the one panel of that tab that
     * reads the database — see `ValueIntelligence::forSightings` for why it
     * was converted here rather than with the rest of the Overview.
     *
     * @param string $b64value
     * @return void
     */
    public function viewSightings($b64value = null)
    {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->forSightings(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            'value_sightings'
        );
    }

    /**
     * The Overview rail's Lifecycle card — three questions that all
     * bear on *is this still worth acting on*.
     *
     * The warninglist line resolves its categories through the
     * Assessment tab's own resolver so the two cannot disagree, and
     * the correlation line is a flag rather than a count —
     * `ValueIntelligence::forLifecycle` has both arguments.
     *
     * @param string $b64value
     * @return void
     */
    public function viewLifecycle($b64value = null)
    {
        $this->set('showsAssessment', $this->__showsAssessment());
        $this->__renderLivePanel($b64value, 'forLifecycle', 'value_lifecycle');
    }

    /**
     * The Overview rail's galaxy matrix card, empty when the value carries
     * no matrix technique.
     *
     * @param string $b64value
     * @return void
     */
    public function viewMatrix($b64value = null)
    {
        $this->__renderLivePanel($b64value, 'forMatrix', 'value_matrix');
    }

    /**
     * One matrix galaxy in full, for the matrix card's modal (`?tab=`).
     *
     * @param string $b64value
     * @param int $galaxyId
     * @return void
     */
    public function viewGalaxyMatrix($b64value = null, $galaxyId = null)
    {
        $this->loadModel('ValueIntelligence');
        $tab = $this->request->query('tab');
        $profile = $this->ValueIntelligence->forGalaxyMatrix(
            $this->Auth->user(),
            $this->__decodeValue($b64value),
            $galaxyId,
            is_string($tab) ? $tab : null
        );
        if ($profile === null) {
            throw new NotFoundException(__('Invalid galaxy'));
        }
        $this->__renderPanel($profile, 'value_galaxy_matrix');
    }

    /**
     * The Overview's external presence card.
     *
     * Live for feeds and sync servers, and a count rather than a list:
     * the detail is the Relationships tab's fourth section, reading the
     * same filtered method so the two cannot disagree
     * (`tabs/03-relationships.md` §20.1).
     *
     * @param string $b64value
     * @return void
     */
    public function viewExternal($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forExternal',
            'value_external'
        );
    }

    /**
     * The Occurrences tab: the facet rail and the table it counts.
     *
     * One endpoint rather than two, unlike the panels above. A facet
     * count and the rows it counts have to be computed from the same
     * fetch or they can disagree with each other, and two endpoints
     * against a moving attribute set is exactly how that happens.
     *
     * @param string $b64value
     * @return void
     */
    public function viewOccurrenceTable($b64value = null)
    {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->forOccurrenceTable(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            'value_occurrence_table'
        );
    }

    /**
     * The Sightings tab: five panels, one endpoint each.
     *
     * Split the other way from the Occurrences tab, and for the
     * opposite reason. There the rail counts the rows beside it, so one
     * fetch is the only honest shape; here the chart, the list and the
     * three rail cards are five readings of the same rows that resolve
     * at their own speed, and the overlay is the widest.
     *
     * **Live since phase 23.** The split earned its keep on the decay
     * envelope — the two panels that drew a curve each spent around
     * 200,000 formula evaluations on it — and phase 5 retired the
     * envelope without collapsing the split: five readings that resolve
     * at their own speed is still the right shape for a tab whose table
     * is the part a reader acts on.
     * prd/value-intelligence-live/23-sightings.md,
     * prd/analyst-profile/06-staleness.md §4.
     *
     * @param string $b64value
     * @return void
     */
    public function viewSightingChart($b64value = null)
    {
        $this->set('showsAssessment', $this->__showsAssessment());
        $this->__renderSightingPanel(
            $b64value,
            'forSightingChart',
            'value_sighting_chart'
        );
    }

    public function viewSightingList($b64value = null)
    {
        $this->__renderSightingPanel(
            $b64value,
            'forSightingList',
            'value_sighting_list'
        );
    }

    /**
     * The rail's relevance card, which until phase 5 was the decay card.
     *
     * `prd/analyst-profile/06-staleness.md` §4 is the retirement and its
     * reason: MISP's decay score is largely a restatement of the value's
     * tags multiplied by a time factor, and the assessment's signal strength
     * ledger already scores those tags directly with a per-row audit
     * trail. So the page takes the time factor and leaves the base
     * score. `decaying_models` itself is untouched — the decaying tool,
     * `excludeDecayed`, `includeDecayScore` and every non-Value-Intelligence
     * caller keep working exactly as they do.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelevance($b64value = null)
    {
        $this->__requireAssessment();
        $this->__renderSightingPanel(
            $b64value,
            'forRelevance',
            'value_relevance'
        );
    }

    public function viewSightingReporters($b64value = null)
    {
        $this->__renderSightingPanel(
            $b64value,
            'forSightingReporters',
            'value_sighting_reporters'
        );
    }

    public function viewSightingAdd($b64value = null)
    {
        $this->__renderSightingPanel(
            $b64value,
            'forSightingAdd',
            'value_sighting_add'
        );
    }

    /**
     * One line per Sightings endpoint rather than five copies of the
     * same four, which is what §14.2 promised the swap would cost.
     *
     * @param string $b64value
     * @param string $method A public ValueIntelligence facade method
     * @param string $element Name under Elements/Values/View
     * @return void
     */
    private function __renderSightingPanel($b64value, $method, $element)
    {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->$method(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            $element
        );
    }

    /**
     * The Relationships tab: three notions of "related", one endpoint
     * each, plus the two rail cards.
     *
     * Three and not one, because the three cost different amounts the
     * moment this goes live. Co-occurrence is a query against the
     * correlation table that can return 1,847 rows; near-matches are
     * re-derived per render and need the CIDR list and an ssdeep
     * recompute; asserted claims are a cheap, complete read of
     * `Relationship` over the value's occurrence UUIDs. One slow
     * correlation query must not hold up the claims, which are the part
     * of this tab a person actually wrote.
     *
     * The co-occurrence scan reads up to 20,000 attribute rows and the
     * asserted claims read a handful of `relationships` rows, so a
     * shared endpoint would make the cheap, human part of this tab wait
     * on the statistical one.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelationCooccurrence($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationCooccurrence',
            'value_relation_cooccurrence',
            array(
                'filters' => $this->__relationFilters(),
                // The panel's own refresh, and the only thing on this
                // page that asks for a read rather than accepting one.
                'fresh' => !empty($this->request->query['fresh']),
            )
        );
    }

    public function viewRelationNearMatch($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationNearMatch',
            'value_relation_near_match'
        );
    }

    public function viewRelationAsserted($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationAsserted',
            'value_relation_asserted'
        );
    }

    /**
     * Section five. Folded with the co-occurrence scan, so this is
     * usually a Redis read — see `ValueIntelligence::forRelationDated`.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelationDated($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationDated',
            'value_relation_dated'
        );
    }

    /**
     * Section six, and the cheapest endpoint on the tab: three indexed
     * lookups against `object_references` and one resolve. Its own
     * action for exactly that reason — it must not queue behind the
     * 20,000-row scan section one can run.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelationReferences($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationReferences',
            'value_relation_references'
        );
    }

    public function viewRelationExternal($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationExternal',
            'value_relation_external'
        );
    }

    /**
     * The Neighbourhood card: markup only. It draws itself from `graph`,
     * and the full graph it opens orders labels by the viewer's profile.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelationGraph($b64value = null)
    {
        $value = $this->__decodeValue($b64value);
        $this->set('pivotLabels', ClassRegistry::init('AnalystProfile')->pivotLabels($this->Auth->user()));
        $this->__renderPanel(array('value' => $value), 'value_relation_graph');
    }

    /**
     * The Neighbourhood graph's opening records, shaped as an event
     * payload shapes them.
     *
     * @param string $b64value
     * @return CakeResponse
     */
    public function graph($b64value = null)
    {
        $this->request->allowMethod(['get']);
        $this->loadModel('ValueGraph');
        return $this->RestResponse->viewData(
            $this->ValueGraph->seed(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            'json'
        );
    }

    /**
     * More occurrences of drawn values: counted with `count`, landed
     * without it.
     *
     * @return CakeResponse
     */
    public function graphOccurrences()
    {
        $this->request->allowMethod(['post']);
        $data = $this->request->data;
        $list = function ($key) use ($data) {
            if (!isset($data[$key]) || !is_array($data[$key])) {
                return array();
            }
            return array_values(array_filter($data[$key], 'is_scalar'));
        };
        $values = array_map('strval', $list('values'));
        if (empty($values)) {
            throw new BadRequestException(__('No value supplied.'));
        }
        $this->loadModel('ValueGraph');
        return $this->RestResponse->viewData(
            $this->ValueGraph->occurrences(
                $this->Auth->user(),
                $values,
                array(
                    'template' => $list('template'),
                    'org' => $list('org'),
                    'year' => $list('year'),
                ),
                array_map('strval', $list('exclude')),
                !empty($data['count'])
            ),
            'json'
        );
    }

    /**
     * The Pivot Explorer's *Enrich* pivot: which expansion modules each
     * type is offered. Read once per page.
     *
     * @return CakeResponse
     */
    public function enrichmentTypes()
    {
        $this->request->allowMethod(['get']);
        $this->loadModel('ValueIntelligence');
        return $this->RestResponse->viewData(
            $this->ValueIntelligence->forEnrichmentTypes($this->Auth->user()),
            'json'
        );
    }

    /**
     * What this organisation already holds for each `{value, type}`.
     * Reads the store; asks no module.
     *
     * @return CakeResponse
     * @throws BadRequestException
     */
    public function enrichmentStored()
    {
        $this->request->allowMethod(['post']);
        $items = array();
        foreach ((array)($this->request->data['items'] ?? array()) as $item) {
            if (is_array($item) && isset($item['value'], $item['type'])
                && is_scalar($item['value']) && is_scalar($item['type'])
            ) {
                $items[] = array('value' => (string)$item['value'],
                    'type' => (string)$item['type']);
            }
        }
        if (empty($items)) {
            throw new BadRequestException(__('No value supplied.'));
        }
        $this->loadModel('ValueIntelligence');
        return $this->RestResponse->viewData(
            $this->ValueIntelligence->forEnrichmentStored(
                $this->Auth->user(),
                array_slice($items, 0, 200)
            ),
            'json'
        );
    }

    /**
     * Run one module against one value and type, or read its stored
     * answer (`mode: stored`), as JSON. The same run as
     * `viewEnrichmentRun`: the module and type are checked against the
     * catalogue this reader would be offered.
     *
     * @return CakeResponse
     * @throws BadRequestException
     */
    public function enrichmentRun()
    {
        $this->request->allowMethod(['post']);
        $data = $this->request->data;
        foreach (array('value', 'type', 'module') as $key) {
            if (!isset($data[$key]) || !is_scalar($data[$key]) || $data[$key] === '') {
                throw new BadRequestException(__('Missing %s.', $key));
            }
        }
        $this->_closeSession(true);
        $this->loadModel('ValueIntelligence');
        return $this->RestResponse->viewData(
            $this->ValueIntelligence->forEnrichmentRun(
                $this->Auth->user(),
                (string)$data['value'],
                array(
                    'module' => (string)$data['module'],
                    'type' => (string)$data['type'],
                    'mode' => isset($data['mode']) && is_scalar($data['mode'])
                        ? (string)$data['mode']
                        : null,
                    'all' => !empty($data['all']),
                )
            ),
            'json'
        );
    }

    public function viewRelationSettings($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationSettings',
            'value_relation_settings'
        );
    }

    /**
     * The rail's third card: which named threats this value sits next
     * to.
     *
     * Its own endpoint rather than a group on the graph card, for the
     * reason the split above gives: it reads events the co-occurrence
     * scan may have skipped as too large, so it answers on values
     * whose neighbourhood table is suppressed entirely and must not
     * queue behind the scan that suppressed it.
     *
     * @param string $b64value
     * @return void
     */
    public function viewRelationThreats($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forRelationThreats',
            'value_relation_threats'
        );
    }

    /**
     * One line per live endpoint, as the Sightings tab's five already
     * have. Named for the Relationships tab until phase 26, which is
     * the third tab to reach for it.
     *
     * @param string $b64value
     * @param string $method A public ValueIntelligence facade method
     * @param string $element Name under Elements/Values/View
     * @return void
     */
    private function __renderLivePanel($b64value, $method, $element,
        array $options = array()
    ) {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->$method(
                $this->Auth->user(),
                $this->__decodeValue($b64value),
                $options
            ),
            $element
        );
    }

    /**
     * The co-occurrence panel's narrowing, as it arrives on the wire.
     *
     * The panel re-requests itself when the reader ticks something its
     * own markup cannot answer — a facet naming thousands of values
     * that rank below the hundred it carries. Nothing here is trusted:
     * `ValueRelationTool` drops every key it did not declare, and the
     * values are only ever compared against tokens it generated
     * itself, so they reach no query and no output.
     *
     * @return array
     */
    private function __relationFilters()
    {
        $query = $this->request->query;
        if (empty($query['f']) || !is_array($query['f'])) {
            return array();
        }
        return $query['f'];
    }

    /**
     * The Enrichment tab: the modules this value could be sent to.
     *
     * **The tab has a memory since phase 11.** It was stateless for
     * three phases because nothing anywhere in MISP recorded that a
     * module had been asked about a value — `Module` is
     * `useTable = false` — and `value_enrichment_runs` is that record.
     * So a row can say *asked 2 h ago* about a module nobody pressed
     * this visit, and the reuse window a profile always declared
     * finally governs something (`13-auto-run.md` §4–5, D25).
     *
     * It says *when*, never *who* (D27).
     *
     * **Two endpoints, as phase 7 left it.** The rail is cheap and
     * local; a run costs an outbound query and up to five seconds. So
     * they resolve separately, which is the per-panel ajax pattern
     * this page already uses, one level further down.
     *
     * **This endpoint still runs nothing**, and neither does opening
     * the tab on an instance that has not turned auto-run on. Where
     * `Plugin.ValueIntelligence_enrichment_auto_run` allows it, the panel
     * arrives carrying a plan and the browser fires the declared
     * modules at `viewEnrichmentRun` — one request each, so a slow
     * module never holds up a fast one, and every one of them is the
     * same request a press makes.
     *
     * `?as=<type>` names the type to match modules on when the reader
     * holds no occurrence of the value.
     *
     * @param string $b64value
     * @return void
     */
    public function viewEnrichment($b64value = null)
    {
        $as = $this->request->query('as');
        $this->__renderLivePanel(
            $b64value,
            'forEnrichment',
            'value_enrichment',
            is_string($as) && $as !== '' ? array('as' => $as) : array()
        );
    }

    /**
     * Run one module against this value and render what came back.
     *
     * **The only action on this page that causes anything to leave the
     * instance**, and the only one that is a POST. It writes nothing
     * to MISP — `Module::queryModuleServer()` is the non-writing call,
     * and `Event::enrichment()`, which turns a response into
     * attributes, is never reached from here — but it spends the
     * instance's quota and announces interest in the value to a third
     * party. A GET carrying that is prefetchable, replayable and
     * crawlable, so it is a POST with a CSRF token.
     *
     * **`validatePost` is off and the CSRF check is not.** Form
     * tampering is what `validatePost` defends and there is no form:
     * two scalars arrive, and neither is trusted anyway — the module
     * name and type are checked against the catalogue this reader
     * would have been shown, in `ValueIntelligence::forEnrichmentRun`.
     * MISP's usual ajax treatment is `unlockedActions`, which would
     * drop both; this endpoint keeps the half that matters.
     *
     * @param string $b64value
     * @return void
     * @throws MethodNotAllowedException
     */
    public function viewEnrichmentRun($b64value = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        /*
         * **Insurance against a locking session handler** (phase 11
         * §7.1). The Enrichment tab fires up to five of these at once,
         * and a handler that takes an exclusive lock for the length of
         * a request would run them strictly one after another — every
         * module still answering, every pane still filling, and the
         * fifth answer arriving after the sum of the first four. A
         * failure that looks exactly like success.
         *
         * **Whether it bites depends on the deployment, and on the
         * common one it does not.** PHP's `files` handler locks, and
         * `core.default.php` asks for `Session.defaults => 'php'`, so
         * an instance on the stock configuration is exposed. The
         * official docker image is not: its FPM pool sets
         * `session.save_handler = redis`, and phpredis leaves
         * `redis.session.locking_enabled` off, so requests on one
         * session already overlap there — which is *measured*, both by
         * this phase and by the `csrfUseOnce` note above, whose
         * lost-update could only happen to requests running at once.
         *
         * So this is one line for the instances the measurement does
         * not cover. Authentication is done by the time an action
         * runs and this one writes nothing back to the session, so it
         * costs nothing where it is not needed. `_closeSession()` keeps
         * the user readable once the session is closed, which an API
         * key's request, having no session to reopen, needs.
         */
        $this->_closeSession(true);
        $this->__renderLivePanel(
            $b64value,
            'forEnrichmentRun',
            'value_enrichment_result',
            array(
                'module' => $this->__runParam('module'),
                'type' => $this->__runParam('type'),
                /*
                 * `auto` asks for the declared behaviour: serve a
                 * fresh stored answer, ask the module only when there
                 * is none. Anything else is a press, and a press
                 * always re-runs. Neither is trusted — the gate and
                 * the reuse window are both re-decided in the model.
                 */
                'mode' => $this->__runParam('mode'),
                // Every element kept rather than the first 200.
                'all' => $this->__runParam('all') === '1',
            )
        );
    }

    /**
     * The Overview's enrichment panel: what the modules have said.
     *
     * **It runs nothing and it reads the store.** That is what makes
     * an enrichment surface possible on the tab that refused one for
     * three phases: the refusal turned on there being nothing here
     * that was not a network request, and `value_enrichment_runs`
     * holds what a module last said as an indexed read of one table.
     * The panel paints at the speed of that read whether or not a
     * module is up.
     *
     * Where the reader's profile marks a module `auto` and the
     * instance permits it, the plan travels out with the markup and
     * the browser fires those at `viewEnrichmentBadge` — after the
     * panel has painted, never during it.
     *
     * The action is never reached on an instance with nothing to show:
     * `ValueIntelligence::forFrame` decides whether the page emits the
     * container at all.
     *
     * @param string $b64value
     * @return void
     */
    public function viewEnrichmentPanel($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forEnrichmentPanel',
            'value_enrichment_panel'
        );
    }

    /**
     * One module's answer, as chips for the Overview panel.
     *
     * `viewEnrichmentRun`'s twin, and everything that docblock says
     * about it is true here: same model call, same `auto` mode, same
     * POST with a CSRF token and `validatePost` off, same closed
     * session, same `perm_add` in the ACL. What differs is the element
     * it renders — a row of chips rather than a pane of objects — and
     * nothing else, so the gate, the reuse window, the in-flight claim
     * and the profile's `never` are decided once, in the model, for
     * both surfaces.
     *
     * @param string $b64value
     * @return void
     * @throws MethodNotAllowedException
     */
    public function viewEnrichmentBadge($b64value = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__(
                'This endpoint only accepts POST requests.'
            ));
        }
        $this->_closeSession(true);
        /*
         * Two surfaces draw this answer and they have different
         * amounts of room: the Overview panel wants every chip the
         * module returned, the hover card wants the headline. One
         * request, one decision about what the module said, two
         * renderings of it — which is the same seam
         * `value_enrichment_badge` already holds between the panel and
         * this endpoint.
         */
        $element = $this->__runParam('shape') === 'chip'
            ? 'value_enrichment_chip'
            : 'value_enrichment_badge';
        $this->__renderLivePanel(
            $b64value,
            'forEnrichmentBadge',
            $element,
            array(
                'module' => $this->__runParam('module'),
                'type' => $this->__runParam('type'),
                'mode' => $this->__runParam('mode'),
            )
        );
    }

    /**
     * The hover card's enrichment strip, asked for by the card itself.
     *
     * Separate from `viewHoverCard` because it is a different kind of
     * cost: that endpoint is one assessment and no network, and this
     * one asks the modules service what a reader could run. Folding it
     * into the card would put an outbound call on every hover of every
     * value, which is the thing the card's whole design refuses.
     *
     * So the card paints, asks for this, and grows once.
     *
     * @param string $b64value
     * @return void
     */
    public function viewHoverEnrichment($b64value = null)
    {
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->forEnrichmentPanel(
                $this->Auth->user(),
                $this->__decodeValue($b64value)
            ),
            'value_hover_enrichment'
        );
    }

    /**
     * One posted scalar, or null.
     *
     * Nothing here validates: the catalogue does, because a check
     * written beside the request would be a second opinion about what
     * this reader may ask, and two of those is how the looser one
     * becomes the answer.
     *
     * @param string $key
     * @return string|null
     */
    private function __runParam($key)
    {
        $data = $this->request->data;
        if (!isset($data[$key]) || !is_string($data[$key])) {
            return null;
        }
        return $data[$key];
    }

    /**
     * The Analyst data tab: where the organisations stand, and the
     * thread underneath it.
     *
     * Two endpoints for what is one fetch, which is the opposite of
     * the Occurrences tab's reasoning and for a compatible one. There
     * the rail counts the rows beside it, so a split could let the two
     * disagree. Here both panels are two readings of one union — the
     * numbers cannot drift because neither is authoritative for the
     * other's rows — while the thread is the part that grows without
     * limit and the part that has no single query behind it: analyst
     * data hangs off an object UUID, so the union over a value's
     * occurrences, their events and their objects is assembled here.
     *
     * **Live since phase 26**, and the split stands for a different
     * reason than it was made for. The standing panel was expected to
     * be the cheap one — four numbers over a set bounded by the
     * organisations on the instance — and it is not: two of its
     * columns count the thread. Both endpoints now read the same
     * union, and the split survives because the two panels still
     * resolve independently in the page.
     *
     * @param string $b64value
     * @return void
     */
    public function viewAnalystStanding($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forAnalystStanding',
            'value_analyst_standing'
        );
    }

    public function viewAnalystThread($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forAnalystThread',
            'value_analyst_thread'
        );
    }

    /**
     * The tab's third panel: the event reports written about the events
     * this value sits in.
     *
     * Its own endpoint rather than a third region of the thread's,
     * because it is a different question of a different model and
     * answers at a different speed — the reports read is one
     * `fetchReports` over the value's events and never waits for the
     * thread's five-anchor union.
     *
     * @param string $b64value
     * @return void
     */
    public function viewAnalystReports($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forAnalystReports',
            'value_analyst_reports'
        );
    }

    /**
     * The tab's fourth panel: the `comment` column of this value's
     * occurrences, one row per distinct sentence.
     *
     * Its own endpoint for the reason the reports list has one — it is
     * a different question of a different shape, answered by two
     * aggregates rather than by the thread's five-anchor union, and it
     * should not wait behind it. It is also the cheapest panel on the
     * tab and the one most values have rows for, so making it the last
     * to arrive would be the wrong way round.
     *
     * @param string $b64value
     * @return void
     */
    public function viewAnalystComments($b64value = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forAnalystComments',
            'value_analyst_comments'
        );
    }

    /**
     * The Timeline tab: the spine, the source lanes and the
     * chronology, in one panel.
     *
     * One endpoint for all three, against every other multi-card tab
     * on this page, because the brush is a single control driving two
     * regions that must already exist when it fires. Three `.ajax-card`
     * requests resolve independently, so a spine that arrived first
     * would be a brush wired to nothing.
     *
     * **Live since phase 25**, and it stays one endpoint: the argument
     * above is about the brush and nothing about reading the database
     * touches it.
     *
     * **The window is in the path, and it is a filter rather than an
     * identity.** `viewHistory`'s period is the panel's subject — what
     * that endpoint returns for one window is a different fragment, top
     * to bottom. This one returns the same spine over the value's whole
     * range whatever window it is given; only the chronology's rows
     * change. It takes the path shape anyway, and `self::period` with
     * it, because a reader of these two actions should not have to
     * learn that one page states a window two ways.
     *
     * Absent or malformed dates mean no window, which is the panel a
     * page load asks for.
     *
     * @param string $b64value
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @return void
     */
    public function viewTimeline($b64value = null, $from = null, $to = null)
    {
        $window = self::__period($from, $to);
        $this->loadModel('ValueIntelligence');
        $this->__renderPanel(
            $this->ValueIntelligence->forTimeline(
                $this->Auth->user(),
                $this->__decodeValue($b64value),
                // `period` also answers `all`, which this panel has no
                // use for: its spine is already the whole range.
                array('window' => is_array($window) ? $window : null)
            ),
            'value_timeline'
        );
    }

    /**
     * The History tab: the counted rail and the occurrence sections it
     * narrows, in one panel.
     *
     * One endpoint, for the Occurrences tab's reason rather than the
     * Timeline tab's. The facet control wires its checkboxes to rows by
     * walking up to the nearest `data-vp-list` region, so the rail and
     * the rows have to arrive inside one container: split across two
     * `.ajax-card`s they resolve independently, and a rail whose rows
     * have not landed yet is a rail wired to nothing.
     *
     * The only panel on this page that takes a period, and it takes it
     * in the path because it is the panel's identity rather than a
     * filter over it: what the endpoint returns for one window is a
     * different fragment, and `reloadAjaxTabIndex` re-fetches a
     * container by URL. Everything else on the tab narrows client-side
     * over rows this already sent.
     *
     * @param string $b64value
     * @param string $from `Y-m-d`, or the literal `all`
     * @param string $to `Y-m-d`
     * @return void
     */
    public function viewHistory($b64value = null, $from = null, $to = null)
    {
        $this->__renderLivePanel(
            $b64value,
            'forHistory',
            'value_history',
            array('window' => self::__period($from, $to))
        );
    }

    /**
     * A period out of two path segments.
     *
     * Anything that is not a well-formed pair falls back to the default
     * window rather than to the whole log: a typo'd URL should land the
     * reader on the bounded page, which is the one that always renders.
     *
     * @param string $from
     * @param string $to
     * @return mixed `all`, a from/to pair, or null for the default
     */
    private static function __period($from, $to)
    {
        if ($from === 'all') {
            return 'all';
        }
        $shape = '/^\d{4}-\d{2}-\d{2}$/';
        if (!preg_match($shape, (string)$from)
            || !preg_match($shape, (string)$to)
        ) {
            return null;
        }
        return $from <= $to
            ? array('from' => $from, 'to' => $to)
            : array('from' => $to, 'to' => $from);
    }

    /**
     * The Assessment tab body.
     *
     * A value whose signals contradict each other needs a different
     * layout, not a different colour: two opposed cases side by side
     * rather than one ledger. Which one is a property of the value, so
     * the lean picks the template.
     *
     * @param string $b64value
     * @return void
     */
    public function viewVerdict($b64value = null)
    {
        /*
         * *Who says what*'s fifth column is an opinion per
         * organisation, and the only thing that knows one is the
         * Collaboration tab's union — 7 to 28 queries (§14.12). The tab
         * asks for it; the Overview card, which has no such column,
         * does not.
         */
        $profile = $this->__verdictFor($b64value,
            array('with_opinions' => true));
        $this->__setOrgGrading();
        /*
         * `ValueLean` rather than a condition here, because
         * `value_verdict_aside.ctp` picks the same branch for the rail
         * and the two are separate requests. Its docblock carries why
         * the lean alone no longer answers this.
         */
        $this->__renderPanel(
            $profile,
            ValueLean::hasConflictedLayout($profile['verdict'])
                ? 'value_verdict_conflicted'
                : 'value_verdict'
        );
    }

    /**
     * The Assessment tab's right rail.
     *
     * One endpoint for the whole rail rather than one per card, unlike
     * the Overview rail: those cards are different questions of
     * different models, while every card here is a reading of the same
     * assessment. The element picks which cards apply.
     *
     * @param string $b64value
     * @return void
     */
    public function viewVerdictAside($b64value = null)
    {
        /*
         * The same union, for the opinion histogram — which is on the
         * contested branch of this rail only. Asked for unconditionally
         * rather than behind a lean test, because the branch is picked
         * inside the element from a verdict this line has to build
         * first, and a second assessment to decide whether to pay for
         * the first would cost more than it saved.
         */
        $this->__renderPanel(
            $this->__verdictFor($b64value,
                array('with_opinions' => true)),
            'value_verdict_aside'
        );
    }

    /**
     * The assessment, for the three endpoints that render one.
     *
     * It is separate from `__renderLivePanel` because `viewVerdict` has
     * to read the answer before it can pick a template.
     *
     * @param string $b64value
     * @return array
     */
    private function __verdictFor($b64value, array $options = array())
    {
        $this->__requireAssessment();
        $this->loadModel('ValueIntelligence');
        return $this->ValueIntelligence->forVerdict(
            $this->Auth->user(),
            $this->__decodeValue($b64value),
            $options
        );
    }

    /**
     * Whether the reader's profile in force wants the assessment drawn.
     *
     * @return bool
     */
    private function __showsAssessment()
    {
        $this->loadModel('AnalystProfile');
        return ValueLabelPriority::showsAssessment(
            $this->AnalystProfile->resolveFor($this->Auth->user())
        );
    }

    /**
     * @return void
     * @throws NotFoundException When the reader's profile switches the
     *                           assessment off
     */
    private function __requireAssessment()
    {
        if (!$this->__showsAssessment()) {
            throw new NotFoundException(__(
                'The assessment is switched off in your analyst profile.'
            ));
        }
    }

    /**
     * The reader's grades and where a new one would land, for the badges
     * on *Who says what*.
     *
     * @return void
     */
    private function __setOrgGrading()
    {
        $this->loadModel('AnalystProfile');
        $this->set('orgGrading',
            $this->AnalystProfile->gradingFor($this->Auth->user()));
    }

    /**
     * Serve one panel: the fragment only, no layout and no chrome, since
     * it is injected into a page that already has both.
     *
     * @param array $profile
     * @param string $element Name under Elements/Values/View
     * @return void
     */
    private function __renderPanel(array $profile, $element)
    {
        $this->set('valueIntelligence', $profile);
        $this->set('valueB64', ValueUrlTool::address($profile['value']));
        $this->layout = false;
        $this->render('/Elements/Values/View/' . $element);
    }

    /**
     * The value this request is about, or a 404.
     *
     * The encoding itself is `ValueUrlTool`'s — two controllers mint and
     * read the same path segment, and its docblock says why the pair does
     * not live on either of them. What stays here is the refusal, so the
     * page's own wording travels with the page.
     *
     * @param string|null $b64value
     * @return string
     * @throws NotFoundException
     */
    private function __decodeValue($b64value)
    {
        if ($b64value === null || $b64value === '') {
            throw new NotFoundException(__('No value supplied.'));
        }
        $address = ValueUrlTool::parse($b64value);
        if ($address === null) {
            throw new NotFoundException(__('Invalid base64 encoding.'));
        }
        if (isset($address['value'])) {
            return $address['value'];
        }
        $found = $this->AttributeValue->findAddressed($address);
        if ($found === null || !$this->__mayRead($found['id'])) {
            throw new NotFoundException(__('Invalid value.'));
        }
        return $found['value'];
    }

    /**
     * An id or a sha256 makes the dictionary supply the text, so it is
     * answered only for a value the reader could have read elsewhere.
     *
     * @param int $id
     * @return bool
     */
    private function __mayRead($id)
    {
        $user = $this->Auth->user();
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        $this->loadModel('MispAttribute');
        return !empty($this->MispAttribute->visibleValueIds($user, [$id], 1));
    }

    /**
     * GET /values/view/<id>, /values/view/sha256:<hex> or /values/view?value=…,
     * or POST {"value": …}. page and limit page the attributes.
     *
     * @param string|null $id
     * @return CakeResponse|void
     */
    public function view($id = null)
    {
        if (!$this->_isRest()) {
            return $this->__valuePage($id);
        }
        $params = $this->__params();
        if ($id !== null) {
            $address = ['id' => $id];
        } elseif (isset($this->request->params['named']['sha256'])) {
            $address = ['sha256' => $this->request->params['named']['sha256']];
        } elseif (isset($params['value'])) {
            $address = ['value' => $params['value']];
        } else {
            throw new BadRequestException(__('Name the value by its id, its sha256 or its text.'));
        }
        list($page, $limit) = $this->__paging($params);
        $value = $this->AttributeValue->findAddressed($address);
        $count = 0;
        $attributes = [];
        if ($value !== null) {
            $this->loadModel('MispAttribute');
            $attributes = $this->MispAttribute->fetchAttributes($this->Auth->user(), [
                'conditions' => ['OR' => [
                    'Attribute.value1_id' => $value['id'],
                    'Attribute.value2_id' => $value['id'],
                ]],
                'flatten' => 1,
                'fields' => ['Event.published', 'Event.sharing_group_id', 'Object.name', 'Object.uuid'],
                'order' => 'Attribute.id DESC',
                'page' => $page,
                'limit' => $limit,
            ], $count, true);
        }
        // A site admin also sees a value nothing visible holds, to delete it
        if ($value === null || ($count === 0 && empty($this->Auth->user()['Role']['perm_site_admin']))) {
            throw new NotFoundException(__('Invalid value.'));
        }
        $summary = [
            'id' => $value['id'],
            'value' => $value['value'],
            'sha256' => hash('sha256', $value['value']),
            'attribute_count' => $count,
        ];
        if ($this->_isRest()) {
            $out = [];
            foreach ($attributes as $row) {
                $out[] = $this->__attribute($row);
            }
            return $this->RestResponse->viewData(['Value' => $summary, 'Attribute' => $out], $this->response->type());
        }
        if (!isset($address['id'])) {
            return $this->redirect(['action' => 'view', $value['id']]);
        }
        $this->request->params['paging']['Attribute'] = [
            'page' => $page,
            'current' => count($attributes),
            'count' => $count,
            'prevPage' => $page > 1,
            'nextPage' => $page * $limit < $count,
            'pageCount' => (int)ceil($count / $limit),
            'order' => null,
            'limit' => $limit,
            'options' => $limit === self::LIMIT ? [] : ['limit' => $limit],
            'paramType' => 'named',
        ];
        $this->set('value', $summary);
        $this->set('attributes', $attributes);
        $this->set('title_for_layout', __('Value'));
    }

    /**
     * POST {"value": …, "mode": "search"|"like"|"exact", "page": …, "limit": …}.
     * search finds the text from the start of a word, like takes a LIKE
     * pattern and exact matches the whole value, ignoring case.
     *
     * @return CakeResponse
     */
    public function search()
    {
        $params = $this->__params();
        $text = $params['value'] ?? null;
        if (!is_scalar($text) || (string)$text === '' || strlen((string)$text) > AttributeValue::MAX_BYTES) {
            throw new BadRequestException(__('Give the text to search for as value.'));
        }
        $text = (string)$text;
        $mode = $params['mode'] ?? 'search';
        if (!in_array($mode, self::SEARCH_MODES, true)) {
            throw new BadRequestException(__('Invalid mode: use search, like or exact.'));
        }
        list($page, $limit) = $this->__paging($params);
        if ($mode === 'exact') {
            $ids = $this->AttributeValue->resolveCi([$text])[$text];
        } else {
            $found = $mode === 'like'
                ? $this->AttributeValue->resolveLike($text, ValueConditionRewriter::OVERFLOW)
                : $this->AttributeValue->resolveSearch($text, ValueConditionRewriter::OVERFLOW);
            if ($found['overflow']) {
                throw new BadRequestException(__('The search matches too many values, narrow it down.'));
            }
            $ids = $found['ids'];
        }
        $this->loadModel('MispAttribute');
        $visible = $this->MispAttribute->visibleValueIds($this->Auth->user(), $ids, $page * $limit);
        $ids = array_slice($visible, ($page - 1) * $limit, $limit);
        $values = $this->AttributeValue->fetchValues($ids);
        $out = [];
        foreach ($ids as $id) {
            if (isset($values[$id])) {
                $out[] = ['Value' => ['id' => $id, 'value' => $values[$id]]];
            }
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * Removes a stored value once nothing refers to it any more, for text that
     * must not stay in the database after its attributes are gone.
     *
     * @param string $id
     * @return CakeResponse|void
     */
    public function delete($id)
    {
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false) {
            throw new NotFoundException(__('Invalid value.'));
        }
        $this->CRUD->delete($id, [
            'validate' => function (array $value) {
                $holders = $this->AttributeValue->holders($value['AttributeValue']['id']);
                $hex = hash('sha256', (string)$value['AttributeValue']['value']);
                $elements = ClassRegistry::init('CollectionElement')->find('count', [
                    'conditions' => ['CollectionElement.element_sha256' => $hex],
                    'recursive' => -1,
                ]);
                if ($elements > 0) {
                    $holders[] = __n('%s collection element', '%s collection elements', $elements, $elements);
                }
                $analystData = $this->__analystDataOn($hex);
                if ($analystData > 0) {
                    $holders[] = __n('%s analyst note, opinion or relationship', '%s analyst notes, opinions or relationships', $analystData, $analystData);
                }
                if (!empty($holders)) {
                    throw new Exception(__('The value is still in use, remove these first: %s.', implode('; ', $holders)));
                }
            },
            'modelFunction' => 'deleteUnheld',
            'afterDelete' => function (array $value) {
                ClassRegistry::init('ValueEnrichmentRun')->purgeValue($value['AttributeValue']['value']);
                $this->loadModel('Log');
                $this->Log->createLogEntry(
                    $this->Auth->user(),
                    'delete',
                    'AttributeValue',
                    $value['AttributeValue']['id'],
                    __('Value #%s deleted from the value dictionary', $value['AttributeValue']['id'])
                );
            },
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    /**
     * How many notes, opinions and relationships name this value by its
     * SHA-256, whoever can see them.
     *
     * @param string $hex lowercase SHA-256 of the value's text
     * @return int
     */
    private function __analystDataOn($hex)
    {
        $count = 0;
        foreach (['Note' => ['object'], 'Opinion' => ['object'], 'Relationship' => ['object', 'related_object']] as $type => $ends) {
            foreach ($ends as $end) {
                $count += ClassRegistry::init($type)->find('count', [
                    'conditions' => ["$type.{$end}_sha256" => $hex],
                    'recursive' => -1,
                    'callbacks' => false,
                ]);
            }
        }
        return $count;
    }

    /**
     * @return array The query string, with the posted fields over it.
     */
    private function __params()
    {
        $params = $this->request->query;
        if ($this->request->is('post') && is_array($this->request->data)) {
            $params = array_merge($params, $this->request->data);
        }
        return $params;
    }

    /**
     * @param array $params
     * @return int[] [page, limit]
     */
    private function __paging(array $params)
    {
        $named = $this->request->params['named'] ?? [];
        $page = filter_var($params['page'] ?? $named['page'] ?? 1, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => self::MAX_PAGE],
        ]);
        $limit = filter_var($params['limit'] ?? $named['limit'] ?? self::LIMIT, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => self::MAX_LIMIT],
        ]);
        if ($page === false || $limit === false) {
            throw new BadRequestException(__('Invalid paging: page from 1 to %s, limit from 1 to %s.', self::MAX_PAGE, self::MAX_LIMIT));
        }
        return [$page, $limit];
    }

    /**
     * @param array $row As fetchAttributes() returns it.
     * @return array
     */
    private function __attribute(array $row)
    {
        $attribute = $row['Attribute'];
        unset($attribute['value1'], $attribute['value2']);
        $event = $row['Event'];
        $attribute['Event'] = [
            'id' => $event['id'],
            'uuid' => $event['uuid'],
            'info' => $event['info'],
            'date' => $event['date'],
            'distribution' => $event['distribution'],
            'sharing_group_id' => $event['sharing_group_id'],
            'published' => $event['published'],
            'timestamp' => $event['timestamp'],
            'Orgc' => $event['Orgc'],
        ];
        if (!empty($attribute['object_id'])) {
            $attribute['Object'] = [
                'id' => $row['Object']['id'],
                'uuid' => $row['Object']['uuid'],
                'name' => $row['Object']['name'],
                'distribution' => $row['Object']['distribution'],
                'sharing_group_id' => $row['Object']['sharing_group_id'],
            ];
        }
        $attribute['Tag'] = [];
        foreach ($row['AttributeTag'] ?? [] as $attributeTag) {
            if (isset($attributeTag['Tag'])) {
                $attribute['Tag'][] = $attributeTag['Tag'];
            }
        }
        return $attribute;
    }
}
