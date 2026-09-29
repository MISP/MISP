# fastLookup batched lookups + pruned IP prefixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** All-hit fastLookup requests take at most ¼ of their #11168 time on every one of the 17 default types, with results identical to #11168.

**Architecture:**
- The equality lookup goes from one `UNION` branch per value to one `valueN IN (…)` query per component per 1,000-value batch. Rows are mapped back to inputs through pad-stripped collation weights.
- Input weights come from one wide single-row `SELECT`.
- Each index generation records which IP prefix lengths it contains, so lookups only generate network tokens for those lengths. A version counter protects lookups against a concurrent change of the set.

**Tech Stack:** PHP 8.1+ / CakePHP 2.x (MISP), PHPUnit 8.5, MariaDB 10.11, Redis 8.2 with RedisBloom, phpredis, Lua.

**Spec:** `docs/superpowers/specs/2026-09-29-fastlookup-batched-design.md`. The spec is amended by rulings A1 and A2 below.

## Spec amendments (controller rulings)

- **A1. Mask encoding.** `p4`/`p6` are fixed-width `'0'`/`'1'` strings (33 and 129 characters; character *n* is length *n*), not hex.
  - Why: they are trivial to OR in Redis Lua 5.1, which has no big integers, and trivial to validate.
  - Cost: 162 bytes per generation.
- **A2. Mask write order.** The masks are updated by their own fenced script, which `add()` runs **before** any token of the same call becomes visible (Bloom `BF.MADD` and posting writes).
  - Why: the invariant that matters is "a visible range token's length is always in the mask". Writing the mask first preserves it: a mask bit without a posting only costs extra tokens. A single-script write would need the mask update inside every chunked posting script.
  - Cost: none.
- **A3. Refresh scope.** When a prefix-version change is detected, the lookup refreshes the masks **once per request**. A second change propagates as `FastLookupIndexUnavailableException`, the same outcome as today's "index changed during the lookup" revision check.

## Global Constraints

- MySQL/MariaDB only. The collation whitelist for weight mapping is `supportsWeights()`: `/^utf8(?:mb3|mb4)?_(?:unicode_ci|general_ci|bin)$/`. Every other collation keeps the per-value `=` branch.
- **Lookup batching:**
  - `AttributeFastLookupTool::BATCH_SIZE = 1000`.
  - `AttributeFastLookupTool::MAX_BATCH_BYTES = 4194304`: the sum of `strlen($db->value($value, 'string'))` in one batch.
  - A batch closes before a value that would exceed either limit.
- `MAX_ROWS = 100000` counts distinct (input index, event id) pairs.
- An input whose pad-stripped weight is `''` for a component never matches that component: no token, no `IN` entry, no fallback branch.
- **Redis generation info fields:**
  - `p4` is a 33-character `[01]` string and `p6` a 129-character `[01]` string.
  - `pv` is a decimal counter.
  - `reserve()` initialises `p4`/`p6` to all `'0'` and `pv` to `'0'`.
  - A generation with none of the three fields is a legacy generation: all lengths apply, and `add()` never creates the fields on it. Any other combination is corrupt.
- Response format, ACL, scope, expansion re-checks, revision checks and error types stay unchanged except where a task says otherwise.
- **Commits:**
  - signed, never `--no-gpg-sign`;
  - gitchangelog prefix (`new:`/`fix:`/`chg:`) with the `[fastLookup]` category;
  - the only trailer is `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, with no session links.
- **Code comments:** minimal, and never referencing tasks, rulings, findings, specs or PRs (repo CLAUDE.md "Code Comments").
- **PHPUnit is 8.5:** use `assertRegExp`, not `assertMatchesRegularExpression`.
- **Running tests:** from the worktree `~/code/misp-fastlookup-batched`, `~/tmp/fl-batched/pu.sh <test file>` runs PHPUnit in container `localhost/misp-live:tmp` against the disposable MariaDB/Redis sockets.
- **Running scripts:** `~/tmp/fl-batched/php.sh <script> /cake /mysql/mysql.sock /redis/redis.sock` runs PHP scripts.
- **Containers:** the containers `fl-batched-db` and `fl-batched-redis` are managed by the controller only. Subagents never start, stop or remove containers.

## Review Focus

1. **Legacy generation with incremental adds** (built by #11168, no masks, receiving new IP ranges after upgrade). Lookups must still find old and new ranges of every length, and `add()` must never create partial masks. Tests: Task 2 Step 1 (`testAddNeverCreatesMasksOnALegacyGeneration`) and Task 4 (legacy e2e).
2. **Mixed-case or padding-variant duplicates in one batch** (`CAFE`, `cafe`, `cafe `, `cafe\u{a0}`). One `IN` entry per weight, and every input index gets the matches. Tests: Task 3 Step 1 (`testEqualWeightsShareOneInEntryAndAllInputsMatch`) and Task 4.
3. **Values longer than 255 characters sharing a 255-character prefix.** The prefix index narrows, but only collation-equal rows match. Test: Task 4 (e2e).
4. **The byte cap with very large values** (1,000 values of 4,096 bytes). Batches must close by bytes. Test: Task 3 Step 1 (`testBatchesCloseAtTheByteCap`).
5. **A concurrent rebuild or new prefix length during a lookup.** A version change triggers one refresh, and a second one is a 503, never a silent miss. Tests: Task 2 (contract) and Task 3 (`testPrefixVersionChangeRefreshesOnceThenFails`).

---

### Task 1: Tokenizer — wide weights query, weight output, stored prefix lengths, pruned query prefixes

**Files:**
- Modify: `app/Lib/Tools/FastLookupValueTool.php`
- Test: `app/Test/FastLookupValueToolTest.php`, `app/Test/AttributeFastLookupTest.php` (fixture responses only, see Step 5)

**Interfaces:**
- Produces:
  - `public function queryTokens(array $values, array $types, &$fallback = null, &$weights = null, ?array $prefixLengths = null): array`
    - `$weights` receives `[input index][component] => pad-stripped weight string`, for every component whose weight was computed (possibly `''`).
    - `$prefixLengths` is `null` for all lengths, else `[4 => [int length => true, …], 6 => [...]]`.
    - Components with an empty weight are **no longer** added to `$fallback`; they are simply absent from the tokens.
  - `public function stripColumnPadding(string $component, string $weight): string`: pad-strips a `WEIGHT_STRING(RTRIM(column))` value exactly like input weights.
  - `prepareScannedAttributes()` rows gain `'networks' => list<array{0:int,1:int}>`: unique `[family (4|6), prefix length]` of the network token the row emits, possibly `[]`.

- [ ] **Step 1: Write failing tests** in `FastLookupValueToolTest.php`. Follow the file's existing helper style (read it first); the fake datasource is `FastLookupTestDatasource` from `app/Test/fixtures/FastLookupConfigurationStub.php`, whose `responses` queue answers `rawQuery()` in order and whose statement `fetch()` returns the queued rows as given. Use a MySQL datasource with a whitelisted collation (`$attribute->db->config['datasource'] = 'Database/Mysql'`, columns `utf8mb3_unicode_ci`) for weight cases.
  - **`testWeightsUseOneWideSelectWithPadColumns`:**
    - `queryTokens(['A', 'b', 'A'], ['domain'], $fallback, $weights)` issues exactly **one** SQL query.
    - The query starts with `SELECT WEIGHT_STRING(RTRIM(CONVERT('A' USING utf8mb3) COLLATE utf8mb3_unicode_ci)) AS `.
    - It contains no `UNION`.
    - It contains one `WEIGHT_STRING(CONVERT(' ' USING utf8mb3) COLLATE utf8mb3_unicode_ci)` pad column.
    - It holds one column per distinct (collation, value), so `'A'` appears once.
    - Queue the reply as a single numeric row, `[ "\x00A\x00 ", "\x00B", "\x00 " ]` (value columns first, then the pad column).
    - Assert `$weights === [0 => ['value1' => "\x00A", 'value2' => "\x00A"], 1 => ['value1' => "\x00B", 'value2' => "\x00B"], 2 => ['value1' => "\x00A", 'value2' => "\x00A"]]`, i.e. trailing pad weights are stripped.
  - **`testMalformedWideWeightRowFailsClosed`:** a reply row with too few columns, a non-string cell, or an empty pad column each throws `RuntimeException('Invalid IOC collation weight response.')`.
  - **`testEmptyWeightProducesNoTokenAndNoFallback`:** a reply giving `''` for `"\u{200b}"` results in `$fallback === []`, `$weights[0]['value1'] === ''`, and no `E` token in the result.
  - **`testPrefixLengthsPruneNetworkTokens`:**
    - `queryTokens(['10.1.2.3'], ['ip-dst'], $f, $w, [4 => [13 => true, 32 => true], 6 => []])` returns exactly 2 `ip_range` tokens.
    - With `null` it returns 33.
    - For `'2001:db8::1'` with `[4 => [], 6 => [128 => true]]` it returns 1.
  - **`testScannedRowsReportNetworkLengths`:** `prepareScannedAttributes()` on the rows below returns these `networks`:
    - `ip-dst` `10.0.0.0/13` gives `[[4, 13]]`;
    - `ip-src` `10.1.2.3` gives `[]` (a bare IP is found by its exact token; only CIDR values carry a network);
    - `ip-dst|port` with value1 `2001:db8::/32` gives `[[6, 32]]`;
    - `domain` gives `[]`.
- [ ] **Step 2: Run the tests; they fail.** `~/tmp/fl-batched/pu.sh app/Test/FastLookupValueToolTest.php` fails on the new tests: queryTokens has no 4th/5th parameter, and the rows have no `networks` key.
- [ ] **Step 3: Implement.**
  - Replace `weights()` with the code below. It keeps today's value expression, deduplicates by (collation, value), appends one pad column per collation not yet memoised, fills `$this->padWeights`, and makes one query per call. The caller bounds its size.

```php
private function weights(array $values)
{
    $columns = [];
    $unique = [];
    $destinations = [];
    $collations = [];
    foreach ($values as $index => $components) {
        foreach ($components as $component => $value) {
            $collation = $this->columns[$component]['collate'];
            $identity = $collation . "\0" . $value;
            if (!isset($unique[$identity])) {
                $unique[$identity] = count($columns);
                $charset = explode('_', $collation, 2)[0];
                $expression = 'CONVERT(' . $this->db->value($value, 'string') . ' USING ' . $charset . ') COLLATE ' . $collation;
                $columns[] = 'WEIGHT_STRING(RTRIM(' . $expression . ')) AS ' . $this->db->name('w' . count($columns));
                $collations[$collation] = true;
            }
            $destinations[$unique[$identity]][] = [$index, $component];
        }
    }
    if (!$columns) {
        return [];
    }
    $valueColumns = count($columns);
    $pads = [];
    foreach (array_keys($collations) as $collation) {
        if (!isset($this->padWeights[$collation])) {
            $pads[count($columns)] = $collation;
            $columns[] = 'WEIGHT_STRING(' . $this->padExpression($collation) . ') AS ' . $this->db->name('p' . count($pads));
        }
    }
    $statement = $this->db->rawQuery('SELECT ' . implode(', ', $columns));
    if (!is_object($statement)) {
        throw new RuntimeException('Could not derive IOC collation weights.');
    }
    try {
        $row = $statement->fetch(PDO::FETCH_NUM);
    } finally {
        $statement->closeCursor();
    }
    if (!is_array($row) || count($row) !== count($columns)) {
        throw new RuntimeException('Invalid IOC collation weight response.');
    }
    $row = array_values($row);
    foreach ($pads as $position => $collation) {
        if (!is_string($row[$position]) || $row[$position] === '') {
            throw new RuntimeException('Invalid IOC collation weight response.');
        }
        $this->padWeights[$collation] = $row[$position];
    }
    $weights = [];
    for ($n = 0; $n < $valueColumns; ++$n) {
        if (!is_string($row[$n])) {
            throw new RuntimeException('Invalid IOC collation weight response.');
        }
        foreach ($destinations[$n] as [$index, $component]) {
            $weights[$index][$component] = self::stripPaddingWeight($row[$n], $this->padWeights[$this->columns[$component]['collate']]);
        }
    }
    return $weights;
}
```

  - Add `stripColumnPadding()`:

```php
/** Pad-strips a WEIGHT_STRING(RTRIM(column)) value like an input weight. */
public function stripColumnPadding(string $component, string $weight): string
{
    return $this->stripPadding($component, $weight);
}
```

  - In `queryTokens()`:
    - add the parameters `&$weights = null, ?array $prefixLengths = null`;
    - after computing `$weights = $this->weights($requests);`, keep it assigned to the by-reference parameter;
    - replace the empty-weight branch with a plain `continue` (no fallback);
    - in the prefix loop, skip lengths absent from `$prefixLengths`:

```php
            foreach ($weights[$index] ?? [] as $component => $weight) {
                if ($weight === '') {
                    continue;
                }
                $tokens[$this->exactToken($component, $weight)] = 'exact';
            }
            ...
            if ($ip !== false && $hasIpType) {
                $family = strlen($ip) === 4 ? 4 : 6;
                for ($prefix = 0, $maximum = strlen($ip) * 8; $prefix <= $maximum; ++$prefix) {
                    if ($prefixLengths !== null && !isset($prefixLengths[$family][$prefix])) {
                        continue;
                    }
                    $networkTokens[] = self::networkToken($ip, $prefix);
                }
            }
```

  - In `prepareScannedAttributes()`, collect the network length next to the network token and add `'networks' => $networks` to each prepared row:

```php
            $networks = [];
            $ipComponent = self::ipComponent($row['type']);
            if ($ipComponent !== null) {
                $network = self::network((string)($row[$ipComponent] ?? ''));
                if ($network !== null) {
                    $tokens[] = self::networkToken($network[0], $network[1]);
                    $networks[] = [strlen($network[0]) === 4 ? 4 : 6, $network[1]];
                }
            }
```

  - Update the docblock of `queryTokens()`: `@param array|null $weights Receives [input index][component] => pad-stripped weight.` and `@param array|null $prefixLengths [4|6 => [length => true]]; null generates every length.`
- [ ] **Step 4: Run the tests; they pass.** `~/tmp/fl-batched/pu.sh app/Test/FastLookupValueToolTest.php` passes.
- [ ] **Step 5: Keep the other suites green.**
  - `AttributeFastLookupTest` fixtures queue weight replies in the old `UNION` row shape (`['input_index' => …, 'component' => …, 'weight' => …, 'pad_weight' => …]`). Convert each such queued reply to the wide single-row shape: one numeric row of the value columns in first-seen (collation, value) order, then the pad column.
  - `testIgnorableWeightsUseSqlToIncludeEmptyComponents` asserts the old behaviour: an empty weight used to take an equality branch. Change it to the new rule under a new name, `testIgnorableOnlyInputNeverMatches`. The expected result is `{}`, and no query after the weights query may contain `"\u{200b}"`.
  - `AttributeFastLookupTool` itself is untouched in this task. Its lookup still takes the `=` path, because `$fallback` is no longer set for empty weights and every non-empty weight with a present exact token still gets its `=` branch.
  - Run `~/tmp/fl-batched/pu.sh app/Test/AttributeFastLookupTest.php`, then `app/Test/FastLookupSqlCollationTest.php` and `app/Test/FastLookupIndexManagerTest.php`. All must be green.
- [ ] **Step 6: Commit** `chg: [fastLookup] One wide collation-weight query, prefix lengths in scanned rows`.

### Task 2: Filter — prefix masks in generation info, prefixLengths(), versioned candidates

**Files:**
- Modify: `app/Lib/Tools/FastLookupFilter.php`
- Test: `app/Test/FastLookupFilterTest.php` (Redis-free), `tests/benchmarks/FastLookupFilterRedisContract.php` (real Redis)

**Interfaces:**
- Consumes (Task 1): prepared rows may carry `'networks' => list<[4|6, int]>`.
- Produces:
  - `class FastLookupPrefixesChangedException extends FastLookupIndexUnavailableException`, declared next to the other exceptions at the top of `FastLookupFilter.php`.
  - `public function prefixLengths(string $generation): array` returns `['version' => string, 'lengths' => null|array{4: array<int,true>, 6: array<int,true>}]`.
    - A legacy generation gives `['version' => '', 'lengths' => null]`.
    - It throws `FastLookupIndexCorruptException` on partial or malformed fields, and via the generation guard.
  - `public function candidates(string $generation, array $queryTokens, int $maximumIds = 100000, ?string $prefixVersion = null): array`
    - When `$prefixVersion !== null`, the Lua script compares `(HGET info 'pv') or ''` with it before any `BF.MEXISTS` and returns `{2}` on a mismatch.
    - PHP throws `FastLookupPrefixesChangedException('The fastLookup IP prefix set changed during the lookup.')`.
    - `$prefixVersion` must be `null`, `''` or `ctype_digit`; otherwise it throws `InvalidArgumentException` before any Redis call.

- [ ] **Step 1: Write the failing Redis-free tests** in `FastLookupFilterTest.php`, using the file's `filter()` and `disconnected()` helpers.
  - `testMalformedNetworksAreRejectedBeforeAnyRedisWrite` (data provider) must throw `InvalidArgumentException` for each of these rows, all with a valid id and one `I` token:
    - `'networks' => 'x'`;
    - `[[5, 1]]`;
    - `[[4, 33]]`;
    - `[[6, 129]]`;
    - `[[4, -1]]`;
    - `[['4', 8]]`;
    - `[[4]]`.
  - `testInvalidPrefixVersionIsRejectedBeforeAnyRedisCall`: `candidates('generation', [], 10, 'x')` and the same with `'-1'` throw `InvalidArgumentException`.
  - `testPrefixLengthsParsesMasks`: use a redis double whose `eval()` returns a canned reply and whose `clearLastError()`/`getLastError()` are no-ops.
    - `[str_repeat('0', 13) . '1' . str_repeat('0', 19), str_repeat('0', 128) . '1', '7']` gives `['version' => '7', 'lengths' => [4 => [13 => true], 6 => [128 => true]]]`.
    - `[false, false, false]` gives `['version' => '', 'lengths' => null]`.
  - `testPartialOrMalformedPrefixStateIsCorrupt` (data provider): each reply below throws `FastLookupIndexCorruptException`:
    - `[false, str_repeat('0',129), '0']`;
    - `[str_repeat('0',32), str_repeat('0',129), '0']`;
    - `[str_repeat('2',33), str_repeat('0',129), '0']`;
    - `[str_repeat('0',33), str_repeat('0',129), 'x']`;
    - `[str_repeat('0',33), str_repeat('0',129), false]`.
- [ ] **Step 2: Run the tests; they fail.** `~/tmp/fl-batched/pu.sh app/Test/FastLookupFilterTest.php` fails on the new tests.
- [ ] **Step 3: Implement.**
  - **In `reserve()`'s first Lua script,** extend the `HSET` of `KEYS[2]` with `'p4', string.rep('0', 33), 'p6', string.rep('0', 129), 'pv', '0'`.
  - **In `add()`:**
    - validate `networks` inside the existing per-row loop;
    - collect `$lengths[4|6][$n] = true`;
    - after validation and **before** the `BF.MADD` loop, run the mask script when any length was collected.

```php
            foreach ($row['networks'] ?? [] as $network) {
                if (!is_array($network) || count($network) !== 2 || !isset($network[0], $network[1])
                    || !is_int($network[0]) || !is_int($network[1]) || !in_array($network[0], [4, 6], true)
                    || $network[1] < 0 || $network[1] > ($network[0] === 4 ? 32 : 128)) {
                    throw new InvalidArgumentException('Malformed prepared fastLookup attribute.');
                }
                $lengths[$network[0]][$network[1]] = true;
            }
```

    - Also reject a present `networks` value that is not an array (`isset($row['networks']) && !is_array($row['networks'])`), with the same message. Initialise `$lengths = [4 => [], 6 => []]` next to `$tokens`.

```php
        if ($lengths[4] || $lengths[6]) {
            $this->evaluate($this->fenceScript() . <<<'LUA'
local p4, p6 = redis.call('HGET', KEYS[2], 'p4'), redis.call('HGET', KEYS[2], 'p6')
if not p4 and not p6 and not redis.call('HGET', KEYS[2], 'pv') then return 0 end
if not p4 or not p6 or #p4 ~= 33 or #p6 ~= 129 or string.find(p4, '[^01]') or string.find(p6, '[^01]') then
    return redis.error_reply('corrupt prefix mask')
end
local function merge(mask, list)
    local bytes, changed = {string.byte(mask, 1, #mask)}, false
    for n in string.gmatch(list, '%d+') do
        local i = tonumber(n) + 1
        if bytes[i] ~= 49 then bytes[i] = 49; changed = true end
    end
    return string.char(unpack(bytes)), changed
end
local n4, c4 = merge(p4, ARGV[2])
local n6, c6 = merge(p6, ARGV[3])
if not (c4 or c6) then return 0 end
redis.call('HSET', KEYS[2], 'p4', n4, 'p6', n6)
redis.call('HINCRBY', KEYS[2], 'pv', 1)
return 1
LUA
                , $fence, [$generation, implode(',', array_keys($lengths[4])), implode(',', array_keys($lengths[6]))]);
        }
```

  - **Add `prefixLengths()`:**

```php
    public function prefixLengths(string $generation): array
    {
        $this->identifier($generation);
        $reply = $this->evaluate($this->guardScript() . <<<'LUA'
local failure = requireGeneration(KEYS[1], KEYS[2], ARGV[1])
if failure then return failure end
return redis.call('HMGET', KEYS[1], 'p4', 'p6', 'pv')
LUA
            , [$this->infoKey($generation), $this->bloomKey($generation)], [$generation]);
        if (!is_array($reply) || count($reply) !== 3) {
            throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
        }
        [$p4, $p6, $pv] = array_map(static function ($field) { return $field === null ? false : $field; }, array_values($reply));
        if ($p4 === false && $p6 === false && $pv === false) {
            return ['version' => '', 'lengths' => null];
        }
        if (!is_string($p4) || !preg_match('/\A[01]{33}\z/', $p4) || !is_string($p6) || !preg_match('/\A[01]{129}\z/', $p6)
            || !is_string($pv) || !ctype_digit($pv)) {
            throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
        }
        $lengths = [4 => [], 6 => []];
        foreach ([4 => $p4, 6 => $p6] as $family => $mask) {
            for ($n = 0, $size = strlen($mask); $n < $size; ++$n) {
                if ($mask[$n] === '1') {
                    $lengths[$family][$n] = true;
                }
            }
        }
        return ['version' => $pv, 'lengths' => $lengths];
    }
```

  - **In `candidates()`:**
    - validate `$prefixVersion` first, right after the generation identifier check;
    - insert it as `ARGV[3]` (`'-'` when null);
    - shift the token pairs by one;
    - check it in Lua.
    - Exact edits:
      - `$args = [$generation, (string)($maximumIds * 21), $prefixVersion ?? '-'];`
      - Lua `for i = 5, #ARGV, 2 do tokens[#tokens + 1] = ARGV[i] end`;
      - in the loop, `local keyIndex, token = tonumber(ARGV[2 + 2 * n]), ARGV[3 + 2 * n]`;
      - after `requireGeneration`: `if ARGV[3] ~= '-' and (redis.call('HGET', KEYS[2], 'pv') or '') ~= ARGV[3] then return {2} end`;
      - PHP: accept `$reply[0]` in `[0, 1, 2]`, and on `2` throw `FastLookupPrefixesChangedException`.
- [ ] **Step 4: Run the tests; they pass.** `~/tmp/fl-batched/pu.sh app/Test/FastLookupFilterTest.php` is green, and `app/Test/FastLookupIndexManagerTest.php` stays green.
- [ ] **Step 5: Real-Redis contract.** Extend `tests/benchmarks/FastLookupFilterRedisContract.php` in its existing assertion style. Read it first to reuse its setup and helpers. Add these checks:
  - After `reserve()`, `prefixLengths()` gives version `'0'` and both families empty.
  - `add()` of a row with `networks [[4, 24]]` sets bit 24 of `p4` and gives version `'1'`. Re-adding the same length leaves the version at `'1'`. Adding `[[4, 32], [6, 64]]` gives version `'2'`.
  - **Legacy:** `HDEL info p4 p6 pv`, then `add()` a row with `[[4, 13]]`. The three fields are still absent, and `prefixLengths()` gives `lengths === null`.
  - A partial state (`HDEL info p6`) makes `prefixLengths()` throw `FastLookupIndexCorruptException`, and `add()` with networks throws `FastLookupIndexUnavailableException`.
  - `candidates()` with `$prefixVersion = '1'` after the version became `'2'` throws `FastLookupPrefixesChangedException`. With `'2'` it answers normally, and with `null` it skips the check.
  - Write order: after `add()` returns, every range token added is present in the Bloom filter and its length bit is set.
  - Run: `cd ~/code/misp-fastlookup-batched && ~/tmp/fl-batched/php.sh tests/benchmarks/FastLookupFilterRedisContract.php /redis/redis.sock`. The output must be `"status": "passed"`.
- [ ] **Step 6: Commit** `new: [fastLookup] Record indexed IP prefix lengths per generation`.

### Task 3: Lookup — 1,000-value batches, IN queries mapped by weight, prefix refresh

**Files:**
- Modify: `app/Lib/Tools/AttributeFastLookupTool.php`, `app/Test/fixtures/FastLookupConfigurationStub.php` (the `FastLookupTestFilter` double)
- Test: `app/Test/AttributeFastLookupTest.php`

**Interfaces:**
- Consumes:
  - Task 1: `queryTokens(…, &$fallback, &$weights, ?array $prefixLengths)` and `stripColumnPadding()`.
  - Task 2: `prefixLengths()`, `candidates(…, ?string $prefixVersion)` and `FastLookupPrefixesChangedException`.
- Produces: `const BATCH_SIZE = 1000; const MAX_BATCH_BYTES = 4194304;`. The API response is unchanged.

- [ ] **Step 1: Update the test double and write failing tests.**
  - In `FastLookupTestFilter`, add these members: `public $prefixes = ['version' => '', 'lengths' => null]; public $prefixReads = 0; public $changes = 0;`.
  - Add `prefixLengths($generation) { ++$this->prefixReads; return $this->prefixes; }`.
  - Extend `candidates($generation, array $tokens, $maximumIds = 100000, $prefixVersion = null)` to record the version in `reads`. It throws `new FastLookupPrefixesChangedException('changed')` while `$this->changes-- > 0`.
  - The stubs file must declare `FastLookupPrefixesChangedException` if it is not loaded. The tests `require_once` `FastLookupFilter.php` first, so a `class_exists` guard is enough.
  - New tests in `AttributeFastLookupTest.php`:
    - **`testEqualWeightsShareOneInEntryAndAllInputsMatch`:**
      - inputs `['CAFE', 'cafe', "cafe\u{a0}"]`, all with the same weight `"\x00C\x00A\x00F\x00E"` after pad stripping; the filter hits `exact` for all three;
      - the queued `value1` reply is `[['event_id' => '7', 'weight' => "\x00C\x00A\x00F\x00E\x00 "]]` and the `value2` reply is `[]`;
      - assert one query contains `` `Attribute`.`value1` IN ('CAFE') ``, exactly one quoted value, no `UNION` and no `` = 'cafe' ``;
      - all three result keys have `event_ids ["7"]`.
    - **`testRowsMapOnlyToInputsWithTheSameWeight`:** a row whose weight equals only input 1's weight adds events to input 1 alone.
    - **`testDuplicatePairsAcrossComponentsCountOnce`:** the same (input, event) returned by `value1` and `value2` counts once toward `MAX_ROWS`. Use a reflection-free check: set up exactly `MAX_ROWS` distinct pairs duplicated across both components, and the lookup must not throw `OverflowException`.
    - **`testBatchesCloseAtTheByteCap`:** 1,000 distinct values of 4,000 bytes that each contain 200 single quotes (quoted size about 4,202 bytes, so 1,000 of them exceed 4 MiB) produce more than one batch. Assert more than one weights query (the queries starting with `SELECT WEIGHT_STRING`), and that no single query exceeds 8 MiB.
    - **`testThousandValuesUseOneBatch`:** 1,000 short values give exactly one weights query and at most 2 `IN` queries.
    - **`testPrefixLengthsAreReadOnceAndPassedToCandidates`:**
      - `prefixes` is `['version' => '3', 'lengths' => [4 => [32 => true], 6 => []]]`;
      - the lookup of `['10.1.2.3']` against `ip-dst` scope reads the prefixes once;
      - the candidates call gets version `'3'` and exactly one `I` token.
    - **`testPrefixVersionChangeRefreshesOnceThenFails`:**
      - with `changes = 1` the lookup succeeds and `prefixReads === 2`;
      - with `changes = 2` it throws `FastLookupIndexUnavailableException`.
  - Update the existing tests that assert the old `UNION`/`=` shape or 100-value batches:
    - `testFallbackSqlPreservesCollationScopeAndSortedOriginalKeys`: the stub datasource is not MySQL, so it keeps the `=` fallback. Keep its assertions.
    - `testMaybePresentExactTokenUsesLiveEqualityWithoutIdRestriction`: now assert `` `Attribute`.`value1` IN ('cafe') `` and `WEIGHT_STRING(RTRIM(`Attribute`.`value1`))`.
    - `testLaterBatchesKeepTheirInputOrdinals` and `testExhaustedBudgetStopsBeforeAnotherCandidateBatch`: use `range(0, 1000)` (1,001 values).
    - `testPortHalvesOfCompositesNeverMatch`: assert the `value2` IN list or `=` branch is restricted with `` `Attribute`.`type` NOT IN ( `` for port composites, whichever path the stub collation takes.
    - Keep each test's intent. Record every changed test name in the report.
- [ ] **Step 2: Run the tests; they fail.** `~/tmp/fl-batched/pu.sh app/Test/AttributeFastLookupTest.php` fails on the new tests.
- [ ] **Step 3: Implement** in `AttributeFastLookupTool::lookup()`.
  - Before the batch loop:

```php
        $filter = $this->manager->filter();
        $prefixes = $filter->prefixLengths($snapshot['generation']);
        $prefixesRefreshed = false;
```

  - The batch loop becomes `foreach ($this->batches($values) as $batch) {`. Inside it, replace tokenization, candidates and the equality section with the code below. The expansion section that follows is unchanged.

```php
            $tokens = $valueTool->queryTokens($batch, $scope['attribute_types'], $fallback, $weights, $prefixes['lengths']);
            try {
                $candidates = $filter->candidates($snapshot['generation'], $tokens, self::MAX_ROWS - $rowCount, $prefixes['version']);
            } catch (FastLookupPrefixesChangedException $e) {
                if ($prefixesRefreshed) {
                    throw $e;
                }
                $prefixesRefreshed = true;
                $prefixes = $filter->prefixLengths($snapshot['generation']);
                $tokens = $valueTool->queryTokens($batch, $scope['attribute_types'], $fallback, $weights, $prefixes['lengths']);
                $candidates = $filter->candidates($snapshot['generation'], $tokens, self::MAX_ROWS - $rowCount, $prefixes['version']);
            }
            $this->validateCandidates($candidates, $batch, $rowCount);
            $pairs = [];
            foreach (['value1', 'value2'] as $component) {
                $restriction = '';
                if (!empty($unindexed[$component])) {
                    $restriction = ' AND ' . $this->db->name('Attribute.type') . ' NOT IN (' . implode(',', $unindexed[$component]) . ')';
                }
                $byWeight = [];
                $inList = [];
                $branches = [];
                foreach ($batch as $index => $value) {
                    if (!$valueTool->representable($value, $component)) {
                        continue;
                    }
                    if (!empty($fallback[$index][$component])) {
                        $branches[] = 'SELECT ' . (int)$index . ' AS ' . $this->db->name('input_index')
                            . ', ' . $this->db->name('Attribute.event_id') . ' AS ' . $this->db->name('event_id')
                            . ' FROM ' . $from . ' WHERE ' . $this->db->name('Attribute.' . $component)
                            . ' = ' . $this->db->value($value, 'string') . $common . $restriction;
                        continue;
                    }
                    // The Bloom filter only proves absence; SQL equality decides.
                    $weight = $weights[$index][$component] ?? '';
                    if ($weight === '' || empty($candidates[$index]['exact'])) {
                        continue;
                    }
                    if (!isset($byWeight[$weight])) {
                        $inList[] = $this->db->value($value, 'string');
                    }
                    $byWeight[$weight][] = $index;
                }
                if ($inList) {
                    $column = $this->db->name('Attribute.' . $component);
                    $sql = 'SELECT DISTINCT ' . $this->db->name('Attribute.event_id') . ' AS ' . $this->db->name('event_id')
                        . ', WEIGHT_STRING(RTRIM(' . $column . ')) AS ' . $this->db->name('weight')
                        . ' FROM ' . $from . ' WHERE ' . $column . ' IN (' . implode(',', $inList) . ')' . $common . $restriction
                        . ' LIMIT ' . (self::MAX_ROWS - $rowCount + 1);
                    foreach ($this->rows($sql) as $row) {
                        if (!is_string($row['weight'] ?? null)) {
                            throw new RuntimeException('Invalid IOC lookup response.');
                        }
                        foreach ($byWeight[$valueTool->stripColumnPadding($component, $row['weight'])] ?? [] as $index) {
                            $this->addPair($matches, $pairs, $index, (string)$row['event_id'], $rowCount);
                        }
                    }
                }
                if ($branches) {
                    $sql = implode(' UNION ', $branches) . ' LIMIT ' . (self::MAX_ROWS - $rowCount + 1);
                    foreach ($this->rows($sql) as $row) {
                        $this->addPair($matches, $pairs, (int)$row['input_index'], (string)$row['event_id'], $rowCount);
                    }
                }
            }
```

  - Add these helpers:
    - `rows()` streams without counting, because pairs are counted;
    - `addPair()` counts distinct pairs;
    - `batches()` implements the count and byte cap.

    The existing `query()` stays for the expansion fetch.

```php
    private function rows(string $sql): Generator
    {
        $statement = $this->db->rawQuery($sql);
        if (!is_object($statement)) {
            throw new RuntimeException('Could not execute the IOC lookup query.');
        }
        try {
            while (($row = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
                yield $row;
            }
        } finally {
            $statement->closeCursor();
        }
    }

    private function addPair(array &$matches, array &$pairs, int $index, string $eventId, &$rowCount)
    {
        if (!isset($pairs[$index][$eventId])) {
            $this->consumeRows(1, $rowCount);
            $pairs[$index][$eventId] = true;
            $matches[$index]['events'][$eventId] = true;
        }
    }

    /** Batches bound both the value count and the SQL-quoted size, so no statement nears max_allowed_packet. */
    private function batches(array $values): array
    {
        $batches = [];
        $batch = [];
        $bytes = 0;
        foreach ($values as $index => $value) {
            $size = strlen($this->db->value($value, 'string'));
            if ($batch && (count($batch) === self::BATCH_SIZE || $bytes + $size > self::MAX_BATCH_BYTES)) {
                $batches[] = $batch;
                $batch = [];
                $bytes = 0;
            }
            $batch[$index] = $value;
            $bytes += $size;
        }
        if ($batch) {
            $batches[] = $batch;
        }
        return $batches;
    }
```

  - Set the constants: `BATCH_SIZE = 1000` and `MAX_BATCH_BYTES = 4194304`. Add `App::uses('FastLookupFilter', 'Tools');` at the top if `FastLookupPrefixesChangedException` is not already reachable through the manager's includes.
  - Check that the `$rowCount === self::MAX_ROWS` guard at the top of the loop still applies.
- [ ] **Step 4: Run the tests; they pass.** `~/tmp/fl-batched/pu.sh app/Test/AttributeFastLookupTest.php` is green. Then run every suite: `for f in app/Test/*FastLookup*Test.php; do ~/tmp/fl-batched/pu.sh $f; done`. All must be green, except the known `FastLookupDeletionIntegrationTest` regression if the controller has not yet brought in its fix; report its state as is.
- [ ] **Step 5: Commit** `chg: [fastLookup] Batch equality lookups into IN queries mapped by collation weight`.

### Task 4: End-to-end equivalence against MariaDB + Redis

**Files:**
- Modify: `tests/benchmarks/FastLookupIntegration.php`

**Interfaces:** consumes the public API (`fastLookup()` through the model, as the runner already does). Read the runner first and reuse its data setup and assertion helpers.

- [ ] **Step 1: Add end-to-end cases**, run with the real MariaDB 10.11 `utf8mb3_unicode_ci` columns and a real Redis index. Each asserts the exact `results` JSON.
  1. **Case and padding variants:**
     - store `domain` `Example.org`;
     - look up `['example.org', 'EXAMPLE.ORG', "example.org ", "example.org\u{a0}"]`; all four match its event;
     - `"example.org\t"`, `"example.org\u{3000}"` and `" example.org"` do not match.
  2. **Long values:**
     - store two `filename|sha256` attributes whose `value1` share the first 255 characters (length 300, different tails);
     - a lookup of each full value matches only its own event;
     - a lookup of the 255-character prefix matches neither.
  3. **Whitespace-only inputs:** `"\u{a0}"`, `"\u{200b}"` and `"  "` return no key at all, even though non-composite attributes have an empty `value2`.
  4. **Pruned prefixes:**
     - store `ip-dst` `10.0.0.0/13` and `ip-src` `10.9.9.9`;
     - look up `10.1.2.3`: it matches the /13 via `ip_ranges`;
     - look up `10.9.9.9`: it matches exactly;
     - read `prefixLengths()` and assert it contains exactly `4 => [13]` (bare IPs are exact tokens, not networks).
  5. **Legacy generation:**
     - `HDEL` `p4`, `p6` and `pv` on the live generation's info key;
     - add a new `ip-dst` `192.168.0.0/16` through the normal mutation path and process the queue;
     - lookups of `192.168.5.5` and `10.1.2.3` both still match;
     - the info key still has no `p4`.
  6. **Duplicates:** the same value submitted 3 times appears once, as today, and the result equals the single-value lookup.
- [ ] **Step 2: Run** `cd ~/code/misp-fastlookup-batched && ~/tmp/fl-batched/php.sh tests/benchmarks/FastLookupIntegration.php /cake /mysql/mysql.sock /redis/redis.sock`. All checks pass. If a case fails, fix the production code in the owning file (Tasks 1–3) within this task, and report that as a deviation.
- [ ] **Step 3: Commit** `chg: [fastLookup] End-to-end coverage for batched equality and pruned prefixes`.

### Task 5: Scale benchmark — honest SQL baseline, CPU seconds, result digests

**Files:**
- Modify: `tests/benchmarks/FastLookupScale.php`

**Interfaces:** env `FL_CPU_STAT` (optional), for example `db=/dbcpu,redis=/rediscpu`: paths to cgroup `cpu.stat` files mounted into the PHP container. The PHP process's own CPU comes from `getrusage()`.

- [ ] **Step 1: Implement.**
  - **(a) SQL baseline.** Replace the `$sqlOnly` body with the batched form: chunks of `AttributeFastLookupTool::BATCH_SIZE`. For each chunk and each component run one query, `SELECT DISTINCT event_id, valueN AS v FROM <from> WHERE valueN IN (<every value and its containment forms, deduplicated>) <common>`. Map rows back in PHP by the lowercased trimmed form, which is enough for the synthetic ASCII data, and count the matched inputs. Keep the header comment accurate: this is the strongest plain-SQL form, and it still misses non-canonical stored CIDRs.
  - **(b) CPU.** Around each lookup timing, read PHP `getrusage()` (`ru_utime` + `ru_stime`) and each `FL_CPU_STAT` file's `usage_usec` before and after. Report `cpu_seconds` as `{php, db, redis, total}` next to `seconds` for every lookup kind and for `sql_only`.
  - **(c) Digests.** For every type and kind, add `results_sha256`: the SHA-256 of `json_encode($response['results'])` with keys in submission order, as returned. This lets two runs on different code be compared.
  - **(d) Repeats.** `FL_RUNS` (default 1) repeats each lookup; report the median `seconds` and `cpu_seconds` over the runs. One warm-up run is done first when `FL_RUNS > 1`.
- [ ] **Step 2: Smoke run.** `cd ~/code/misp-fastlookup-batched && FL_PER_TYPE=2000 FL_LOOKUP=500 FL_SQL_BASELINE=1 FL_RUNS=2 FL_OUT=/out/smoke.json ~/tmp/fl-batched/php.sh tests/benchmarks/FastLookupScale.php /cake /mysql/mysql.sock /redis/redis.sock`. It completes, and every type has `results_sha256`, `cpu_seconds` and the SQL baseline fields.
- [ ] **Step 3: Commit** `chg: [fastLookup] Scale benchmark reports CPU, result digests and a batched SQL baseline`.

### Task 6 (controller): Acceptance run, docs, PR

Not dispatched as an implementer task. The controller runs it after the final whole-branch review.

- [ ] Wait for a quiet host: the 1-minute load average must be below `nproc`.
- [ ] Run the gate against both builds on the same containers, back to back:
  - the new branch;
  - a detached worktree of `feature/attributes-fast-lookup-bloom` with this branch's `FastLookupScale.php` copied in.
  - Settings: `FL_PER_TYPE=100000 FL_PER_EVENT=100 FL_LOOKUP=10000 FL_SQL_BASELINE=1 FL_RUNS=3`, with CPU stat files mounted.
- [ ] The gate passes when all of these hold:
  - every type: new all-hit `seconds` ≤ 0.25 × old, and `cpu_seconds.total` ≤ 0.25 × old;
  - misses and expansions are not slower;
  - `results_sha256` is equal for every type × kind.
- [ ] Update `docs/development/fastlookup.md`: batching, prefix masks, whitespace-only inputs and the new sizing/latency table.
- [ ] Remove `docs/superpowers/` from the branch.
- [ ] Draft the stacked PR, base `feature/attributes-fast-lookup-bloom` on the fork or #11168's branch as appropriate, with a BLUF, a priority tag and the honest Bloom-vs-SQL table.
