<?php

require 'functions.php';

if ($_SERVER['REQUEST_METHOD'] == 'GET'){
    $id = $_GET['id'];

    $db = get_db_conn();
    $sql = 'SELECT * FROM posts WHERE id=? LIMIT 1';
    $sth = $db->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY));
    if ($sth->execute(array($id))) {
        $post = $sth->fetch();
        if (empty($post['password'])){
            render('show', array('post' => $post));
        } else {
            $post['password'] = '';
            render('show_input_pass', array('post' => $post));
        }
    }
    render_404();
} else if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = $_REQUEST['id'];
    $db = get_db_conn();
    $sql = 'SELECT * FROM posts WHERE id=? LIMIT 1';
    $sth = $db->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY));
    if ($sth->execute(array($id))) {
        $post = $sth->fetch();
        if (my_own_hash($_POST['password']) === $post['password']) {
            $post['content'] = decrypt_content($post['content']);
            $_GET['id'] = $post['id'];
            render('show', array('post' => $post));
        } else {
            render_404();
        }
    }
}
