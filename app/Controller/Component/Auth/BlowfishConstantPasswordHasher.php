<?php
App::uses('BlowfishPasswordHasher', 'Controller/Component/Auth');

class BlowfishConstantPasswordHasher extends BlowfishPasswordHasher
{
    /**
     * @param string $password
     * @param string $hashedPassword
     * @return bool
     */
    public function check($password, $hashedPassword)
    {
        return hash_equals($hashedPassword, Security::hash($password, 'blowfish', $hashedPassword));
    }
}
