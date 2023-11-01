<?php
	$conn = new MySqli("localhost:3306", "root", "1234", "loja");
    if(!$conn){
        die("Erro ao conectar ao banco de dados.");
    }
?>