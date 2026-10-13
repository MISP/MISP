<?php

/**
 * What has moved through a wallet.
 *
 * **`btc_steroids` emits this, free and unauthenticated.** It returns
 * a `btc-wallet` carrying the balance and the totals received and
 * sent, and one `btc-transaction` per movement carrying its time, its
 * net value to this wallet, and the addresses on both sides. The fiat
 * values are sent only where the rate for that day could be fetched.
 *
 * Four templates are claimed because the ecosystem splits the same
 * answer two ways: a wallet and its transactions as separate objects,
 * or one chain-agnostic address object carrying its own totals.
 *
 * **A transaction's counterparties are the addresses that are not the
 * wallet's own.** `btc-address` is a repeating relation, and the
 * producer sends the wallet being described first and whoever it
 * exchanged value with after it — so reading one address gives the
 * page the value it is already on, which is the one address that
 * cannot be pivoted to. The wallet object is what says which one that
 * is, and where a producer sends transactions with no wallet beside
 * them there is no privileged address and every party is a
 * counterparty.
 */
class CryptoFlowRenderer extends ValueRendererBase
{
    public $id = 'crypto-flow';

    public $templates = array(
        'coin-address',
        'btc-wallet',
        'btc-transaction',
        'cryptocurrency-transaction',
    );

    public $compact = 'Values/Renderers/crypto_flow_compact';

    public $full = 'Values/Renderers/crypto_flow_full';

    public $eventUse = self::EVENT_EACH;

    public function __construct()
    {
        $this->description = __('A wallet\'s balance and the'
            . ' transactions through it.');
    }

    public function subjectsOf(array $object)
    {
        $wallet = $this->walletAddressOf($object);
        if ($wallet !== null) {
            return array($wallet);
        }
        return array_merge(
            $this->values($object, 'btc-address'),
            $this->values($object, 'address')
        );
    }

    /**
     * One group per wallet, holding the transactions that name it.
     * Transactions naming no wallet of the set share one group.
     */
    public function groupsOf(array $objects)
    {
        $groups = array();
        foreach ($objects as $object) {
            $address = $this->walletAddressOf($object);
            if ($address === null) {
                continue;
            }
            if (!isset($groups[$address])) {
                $groups[$address] = array(
                    'subject' => $address,
                    'kind' => self::SUBJECT_NAMED,
                    'objects' => array(),
                );
            }
            $groups[$address]['objects'][] = $object;
        }
        $loose = array();
        foreach ($objects as $object) {
            if ($this->walletAddressOf($object) !== null) {
                continue;
            }
            $joined = false;
            foreach (array_unique($this->subjectsOf($object)) as $address) {
                if (isset($groups[$address])) {
                    $groups[$address]['objects'][] = $object;
                    $joined = true;
                }
            }
            if (!$joined) {
                $loose[] = $object;
            }
        }
        $out = array_values($groups);
        if (!empty($loose)) {
            $out[] = array(
                'subject' => null,
                'kind' => self::SUBJECT_NONE,
                'objects' => $loose,
            );
        }
        return $out;
    }

    public function subjectWords()
    {
        return array(
            'one' => __('wallet'),
            'many' => __('wallets'),
            'none' => __('No wallet named'),
            'none_title' => __('Transactions naming no wallet of this event'),
            'none_group' => __('of transactions naming no wallet of this'
                . ' event'),
        );
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->walletOf($object) !== null
                || $this->transactionOf($object) !== null
            ) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        /*
         * The wallet is resolved first and in a pass of its own: it
         * carries the one address a transaction must not offer as a
         * counterparty, and the objects arrive in whatever order the
         * runs were read in.
         */
        $wallet = null;
        foreach ($objects as $object) {
            $found = $this->walletOf($object);
            if ($found !== null
                && ($wallet === null
                    || ($found['ran_at'] ?? 0) > ($wallet['ran_at'] ?? 0))
            ) {
                $wallet = $found;
            }
        }
        $transactions = array();
        foreach ($objects as $object) {
            $transaction = $this->transactionOf(
                $object,
                $wallet === null ? null : $wallet['address']
            );
            if ($transaction !== null) {
                $transactions[] = $transaction;
            }
        }
        usort($transactions, function ($a, $b) {
            return ($b['at'] ?? 0) - ($a['at'] ?? 0);
        });
        return array(
            'wallet' => $wallet,
            'transactions' => $transactions,
            'count' => count($transactions),
            /*
             * The last movement is the fact the compact form leads
             * with — a wallet with a balance and no movement in two
             * years is a different thing from one that moved this
             * morning — and it comes off the transactions where there
             * are any, because a wallet object's own `last-seen` is
             * when the service last looked.
             */
            'last_movement' => empty($transactions)
                ? ($wallet['last_seen'] ?? null)
                : $transactions[0]['at'],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return string|null
     */
    private function walletAddressOf(array $object)
    {
        $name = $object['name'] ?? null;
        if ($name === 'btc-wallet') {
            return $this->value($object, 'wallet-address');
        }
        if ($name === 'coin-address') {
            return $this->firstValue($object, array(
                'address', 'address-crypto', 'address-xmr',
            ));
        }
        return null;
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function walletOf(array $object)
    {
        $name = $object['name'] ?? null;
        if ($name === 'btc-wallet') {
            $balance = $this->number(
                $this->value($object, 'balance_BTC')
            );
            if ($balance === null) {
                return null;
            }
            return array(
                'address' => $this->value($object, 'wallet-address'),
                'symbol' => 'BTC',
                'balance' => $balance,
                'received' => $this->number(
                    $this->value($object, 'BTC_received')
                ),
                'sent' => $this->number(
                    $this->value($object, 'BTC_sent')
                ),
                'transactions' => null,
                'last_seen' => $this->stamp(
                    $this->value($object, 'time')
                ),
                'module' => $object['module'] ?? null,
                'ran_at' => $object['ran_at'] ?? null,
            );
        }
        if ($name !== 'coin-address') {
            return null;
        }
        $balance = $this->number(
            $this->value($object, 'current-balance')
        );
        $received = $this->number(
            $this->value($object, 'total-received')
        );
        if ($balance === null && $received === null) {
            return null;
        }
        return array(
            'address' => $this->firstValue($object, array(
                'address', 'address-crypto', 'address-xmr',
            )),
            'symbol' => $this->value($object, 'symbol'),
            'balance' => $balance,
            'received' => $received,
            'sent' => $this->number(
                $this->value($object, 'total-sent')
            ),
            'transactions' => $this->number(
                $this->value($object, 'total-transactions')
            ),
            'last_seen' => $this->stamp(
                $this->firstValue($object, array(
                    'last-updated', 'last-seen',
                ))
            ),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }

    /**
     * @param array $object
     * @param string|null $subject The wallet's own address, where one
     *                             is known, so it is not offered as a
     *                             counterparty to itself
     * @return array|null
     */
    private function transactionOf(array $object, $subject = null)
    {
        $name = $object['name'] ?? null;
        if ($name !== 'btc-transaction'
            && $name !== 'cryptocurrency-transaction'
        ) {
            return null;
        }
        $number = $this->value($object, 'transaction-number');
        $at = $this->stamp($this->value($object, 'time'));
        if ($number === null && $at === null) {
            return null;
        }
        $counterparties = $this->counterpartiesOf($object, $subject);
        return array(
            'number' => $number,
            'at' => $at,
            'counterparty' => empty($counterparties)
                ? null : $counterparties[0],
            'counterparties' => $counterparties,
            'symbol' => $this->value($object, 'symbol')
                ?? ($name === 'btc-transaction' ? 'BTC' : null),
            'value' => $this->number($this->firstValue($object, array(
                'value_BTC', 'value',
            ))),
            'value_eur' => $this->number(
                $this->value($object, 'value_EUR')
            ),
            'value_usd' => $this->number(
                $this->value($object, 'value_USD')
            ),
            'module' => $object['module'] ?? null,
        );
    }

    /**
     * Every address on a transaction that is not the wallet's own, in
     * the order the producer sent them and deduplicated.
     *
     * A transaction legitimately names the same counterparty twice —
     * change returned to an address that was also an input — and
     * listing it twice would read as two parties.
     *
     * @param array $object
     * @param string|null $subject
     * @return array
     */
    private function counterpartiesOf(array $object, $subject)
    {
        $addresses = array_merge(
            $this->values($object, 'btc-address'),
            $this->values($object, 'address')
        );
        $out = array();
        foreach ($addresses as $address) {
            if ($subject !== null && $address === $subject) {
                continue;
            }
            if (!in_array($address, $out, true)) {
                $out[] = $address;
            }
        }
        return $out;
    }
}
