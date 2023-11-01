<?php
// Inicia a sessão para gerenciar informações do usuário logado
session_start();

// Remove as variáveis de sessão relacionadas ao usuário
unset($_SESSION["ra"]);
unset($_SESSION["nome"]);

// Destrói a sessão, removendo todas as variáveis de sessão
session_destroy();

// Redireciona de volta para a página de login (index.php)
header("Location: index.html");
exit;
