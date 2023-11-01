<?php

include "conecta.php";

echo "<h2>Cadastrado com sucesso</h2>";
$nome = $_POST["nome"];
$email = $_POST["email"];
$senha = $_POST["senha"];




$sql = "INSERT INTO loja.usuarios(nome,email,senha) VALUES(?,?,?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("sss",$nome,$email,$senha);
$stmt->execute();

header("location: ../index.html");


