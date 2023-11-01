<?php


// Inicia a sessão para gerenciar informações do usuário logado
session_start();

// Verifica se o formulário foi submetido e se os campos 'ra' e 'senha' não estão vazios
if (empty($_POST) || empty($_POST["email"]) || empty($_POST["senha"])) {
    // Se algum dos campos estiver vazio, redireciona de volta para a página de login (index.php)
    header("location: indexlogin.html");
}

// Inclui o arquivo de configuração do banco de dados
include "conecta.php";

// Obtém os valores de 'ra' e 'senha' do formulário
$usuario = $_POST["email"];
$senha = $_POST["senha"];

// Cria uma consulta SQL para buscar um usuário com o 'ra' e 'senha' fornecidos
$sql = "SELECT * FROM usuarios WHERE email = '$usuario' AND senha = '$senha'";

// Executa a consulta no banco de dados
$res = $conn->query($sql) or die($conn->error);

// Obtém a primeira linha de resultados como um objeto
$row = $res->fetch_object();

// Obtém a quantidade de linhas retornadas pela consulta
$qtd = $res->num_rows;

// Verifica se a consulta retornou pelo menos um resultado (usuário válido)
if ($qtd > 0) {
    // Define variáveis de sessão para o usuário logado
    $_SESSION["email"] = $usuario;
    $_SESSION["nome"] = $row->nome;

    // Redireciona para a página do dashboard (dashbord.php) após o login bem-sucedido
    header('Location: ../index.html');
} else {
    // Se não houver resultados na consulta, exibe um alerta e redireciona de volta para a página de login (index.php)
    print "<script>alert('Email ou senha inválidos');</script>";
    print "<script>location.href='indexlogin.html';</script>";
}




/*
	session_start();

	if(empty($_POST) or (empty($_POST["ra"]) or (empty($_POST["senha"]) ) ) ){
		print "<script>location.href='index.php';</script>";
	}

	include("config.php");

	$usuario = $_POST["ra"];
	$senha   = $_POST["senha"];

    $stmt = $conn->prepare("SELECT * FROM usuarios WHERE ra = ? LIMIT 1");
    $stmt->bind_param("s", $usuario);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        if (password_verify($senha, $row["senha"])) {
            $_SESSION["ra"] = $usuario;
            $_SESSION["nome"] = $row["nome"];
            $_SESSION["tipo"] = $row["tipo"];
            header("Location: dashboard.php"); // Redireciona para a página de dashboard
            exit();
        } 	else{
            unset($usuario);
            print "<script>alert('Usuário e/ou Senha incorretos!');</script>";
            print "<script>location.href='index.php';</script>";
        }
    
    }




/* session_start();

if (empty($_POST) || empty($_POST["ra"]) || empty($_POST["senha"])) {
    header("Location: index.php"); // Redireciona para a página de login
    exit();
}

include("config.php");

$usuario = $_POST["ra"];
$senha = $_POST["senha"];

// Use declarações preparadas para proteger contra injeção de SQL
$stmt = $conn->prepare("SELECT * FROM usuarios WHERE ra = ? LIMIT 1");
$stmt->bind_param("s", $usuario);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $row = $result->fetch_assoc();
    if (password_verify($senha, $row["senha"])) {
        $_SESSION["ra"] = $usuario;
        $_SESSION["nome"] = $row["nome"];
        $_SESSION["tipo"] = $row["tipo"];
        header("Location: dashboard.php"); // Redireciona para a página de dashboard
        exit();
    }
}

// Se o login falhar
header("Location: index.php?error=1"); // Você pode adicionar um parâmetro para indicar o erro
exit();
?>
*/