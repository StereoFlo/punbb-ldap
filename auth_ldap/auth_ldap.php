<?php

require "src/adLDAP.php";

global $forum_db;

$connect = [
    'account_suffix'     => '', // suffix fo you domain @domain.ru
    'base_dn'            => '', // base dn dc=domain,dc=ru
    'domain_controllers' => [''] // you domain controllers, separated on comma 192.168.1.1, 192.168.1.2
];

$la = new adLDAP($connect);

$ldap_user = $la->authenticate($form_username, $form_password);

if ($ldap_user !== false) {
    $query = [
        'SELECT' => 'id',
        'FROM'   => 'users',
        'WHERE'  => 'username = \'' . $forum_db->escape($form_username) . '\''
    ];
    $row = $forum_db->query_build($query) || error(__FILE__, __LINE__);

    while ($UserID = $forum_db->fetch_row($row)) {
        $login = $UserID[0];
    }

    if (!empty($login)) {
        $salt = random_key(12);
        $password_hash = forum_hash($form_password, $salt);
        $update_query = [
            'UPDATE' => 'users',
            'SET'    => 'password = \'' . $forum_db->escape($password_hash) . '\', salt=\'' . $forum_db->escape($salt) . '\'',
            'WHERE'  => 'id =\'' . $login . '\''
        ];
        $forum_db->query_build($update_query) or error(__FILE__, __LINE__);
    } else {
        $initial_group_id = ($forum_config['o_regs_verify'] == '0') ? $forum_config['o_default_user_group'] : FORUM_UNVERIFIED;
        $salt = random_key(12);
        $password_hash = forum_hash($form_password, $salt);
        $user = $la->user()->info($form_username, ["mail", "displayname", "title", "sAMAccountName"]);
        $user_info = [
            //'realname'			=> $user[0]['displayname'][0],
            //'title'				=> $user[0]['title'][0],
            'username' => $user[0]['samaccountname'][0],
            'group_id' => $initial_group_id,
            'salt' => $salt,
            'password' => $form_password,
            'password_hash' => $password_hash,
            'email' => $user[0]['mail'][0],
            'email_setting' => $forum_config['o_default_email_setting'],
            'timezone' => $_POST['timezone'],
            'dst' => isset($_POST['dst']) ? '1' : '0',
            'language' => $language,
            'style' => $forum_config['o_default_style'],
            'registered' => time(),
            'registration_ip' => get_remote_address(),
            'activate_key' => ($forum_config['o_regs_verify'] == '1') ? '\'' . random_key(8, true) . '\'' : 'NULL',
            'require_verification' => ($forum_config['o_regs_verify'] == '1'),
            'notify_admins' => ($forum_config['o_regs_report'] == '1')
        ];

        !($hook = get_hook('rg_register_pre_add_user')) ?: eval($hook);
        add_user($user_info, $new_uid);
        $expire = time() + $forum_config['o_timeout_visit'];
        forum_setcookie($cookie_name, base64_encode($new_uid . '|' . $password_hash . '|' . $expire . '|' . sha1($salt . $password_hash . forum_hash($expire, $salt))), $expire);
        redirect(forum_link($forum_url['index']), $lang_profile['Reg complete']);
    }

}