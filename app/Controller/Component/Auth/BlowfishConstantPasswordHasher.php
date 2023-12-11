<?php
App::uses('AbstractPasswordHasher', 'Controller/Component/Auth');

class BlowfishConstantPasswordHasher extends AbstractPasswordHasher
{
    /**
     * @param string $password
     * @return string
     */
    public function hash($password)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT);
        if ($hash === false) {
            throw new RuntimeException('Could not generate hashed password');
        }
        return $hash;
    }

    /**
     * @param string $password
     * @param string $hashedPassword
     * @return bool
     */
    public function check($password, $hashedPassword)
    {
        return password_verify($password, $hashedPassword);
    }
}
