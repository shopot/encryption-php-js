<?php

define('AES_METHOD', 'aes-256-cbc');

$password = 'lbwyBzfgzUIvXZFShJuikaWvLJhIVq36';

function encrypt($message, $password)
{
    if (OPENSSL_VERSION_NUMBER <= 268443727) {
        throw new RuntimeException('OpenSSL Version too old, vulnerability to Heartbleed');
    }
    
    $iv_size        = openssl_cipher_iv_length(AES_METHOD);
    $iv             = openssl_random_pseudo_bytes($iv_size);
    $ciphertext     = openssl_encrypt($message, AES_METHOD, $password, OPENSSL_RAW_DATA, $iv);
    $ciphertext_hex = bin2hex($ciphertext);
    $iv_hex         = bin2hex($iv);
    return "$iv_hex:$ciphertext_hex";
}
function decrypt($ciphered, $password) {
    $iv_size    = openssl_cipher_iv_length(AES_METHOD);
    $data       = explode(":", $ciphered);
    $iv         = hex2bin($data[0]);
    $ciphertext = hex2bin($data[1]);
    return openssl_decrypt($ciphertext, AES_METHOD, $password, OPENSSL_RAW_DATA, $iv);
}
