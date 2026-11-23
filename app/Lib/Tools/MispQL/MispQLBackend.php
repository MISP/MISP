<?php

/**
 * What MispQLRunner needs from MISP, for one user. Tables are MispQL table
 * names; bodies are the restSearch bodies plans hold.
 */
interface MispQLBackend
{
    /**
     * Checks the body's query and order as the table's restSearch would,
     * without reading data.
     *
     * @param string $table
     * @param array $body
     * @return void
     * @throws ComplexQueryException
     */
    public function validate($table, array $body);

    /**
     * Runs the body through restSearch.
     *
     * @param string $table
     * @param array $body
     * @return array result (a string, or an object with intoString()), count
     *   (restSearch's element counter), filters (as run, with the limit the
     *   role allowed), and whatever the caller needs to send the result as
     *   restSearch would
     * @throws ComplexQueryException
     */
    public function search($table, array $body);

    /**
     * @param string $table
     * @return array the table's queryDescribe answer
     */
    public function describe($table);

    /**
     * @return string[] the tables the user may describe
     */
    public function tables();

    /**
     * @return array email, role and org of the user
     */
    public function whoami();
}
