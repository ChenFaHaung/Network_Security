<?php

require 'functions.php';

$db = get_db_conn();

$posts = $db->query('SELECT id, title, content FROM posts')->fetchAll(PDO::FETCH_ASSOC);

# Render the view
render('index', array('posts' => $posts));
