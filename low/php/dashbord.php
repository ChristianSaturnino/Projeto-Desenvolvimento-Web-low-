<?php
session_start();

// Verifica se a sessão está vazia ou se o usuário não está logado
if (empty($_SESSION) || !isset($_SESSION["nome"])) {
    header("Location: index.html"); // Redireciona para a página de login
    exit();
}

// Agora o usuário está logado, você pode exibir a página de dashboard
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
</head>
<body>
    <h1>LOGADO COM SUCESSO</h1>

    <?php
        echo "Olá, " . $_SESSION["nome"];
    ?>

    <a href="logout.php" class="btn btn-danger">Sair</a>
</body>
</html>
