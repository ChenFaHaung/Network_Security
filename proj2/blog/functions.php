<?php

function my_own_hash($input)
{
  $magic1 = 1345345333;
  $magic2 = 0x12345671;
  $sum = 7;  $tmp = null;
  $len = strlen($input);
  for ($i = 0; $i < $len; $i++) {
    $byte = substr($input, $i, 1);
    if ($byte == ' ' || $byte == "\t")
        continue;
    $tmp = ord($byte);
    $magic1 ^= ((($magic1 & 63) + $sum) * $tmp) + (($magic1 << 8) & 0xFFFFFFFF);
    $magic2 += (($magic2 << 8) & 0xFFFFFFFF) ^ $magic1;
    $sum += $tmp;
  }
  $out_a = $magic1 & ((1 << 31) - 1);
  $out_b = $magic2 & ((1 << 31) - 1);
  $output = sprintf("%08x%08x", $out_a, $out_b);
  return $output;
}

function get_db_conn()
{
    require 'config.php';
    return new PDO('mysql:host=localhost;dbname=ns2017spring_Bob;charset=utf8', $db_config['user'], $db_config['pass']);
}

function render_404() {
  header('This is not the page you are looking for', true, 404);
  render('404');
}

function encrypt_content($content) {
  require 'config.php';
  
  $cipher = 'aes-256-cbc';
  $ivSize  = openssl_cipher_iv_length($cipher);
  $ivData  = openssl_random_pseudo_bytes($ivSize);

  $encripted = openssl_encrypt($content,
                            $cipher,
                            $blog_config['encrypt_key'],
                            OPENSSL_RAW_DATA,
                            $ivData);

  return base64_encode($ivData . $encripted);
}

function decrypt_content($content) {
  require 'config.php';

  $cipher = 'aes-256-cbc';  
  $ivSize  = openssl_cipher_iv_length($cipher);

  $content = base64_decode($content);
  $ivData   = substr($content, 0, $ivSize);

  $encData = substr($content, $ivSize);

  $output = openssl_decrypt($encData, 
                            $cipher, 
                            $blog_config['encrypt_key'], 
                            OPENSSL_RAW_DATA, 
                            $ivData);
  return $output;
}

function redirect($target) {
  require 'config.php';
  header("Location: ".$env_config['root_path'].'/'.$target);
  exit();
}

function render($view_name, $data = NULL) {
  require 'views/'.$view_name.'.php';
  exit();
}
