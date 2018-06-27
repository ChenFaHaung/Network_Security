<?php

require 'functions.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST'){
    $db = get_db_conn();

    if (empty($_POST['title']) || empty($_POST['content'])) {
        render_404();
    }
    if (!empty($_POST['password'])){
        $sql = 'INSERT INTO posts (title, content, password) VALUE (:title, :content, :password)';
        $post = array(':title' => $_POST['title'],
                      ':content' => encrypt_content($_POST['content']),
                      ':password' => my_own_hash($_POST['password']));
    } else {
        $sql = 'INSERT INTO posts (title, content) VALUE (:title, :content)';
        $post = array(':title' => $_POST['title'], ':content' => $_POST['content']);
    }
    
    $sth = $db->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY));
    $sth->execute($post);
} else if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    render('create');
} else {
    render_404();
}
