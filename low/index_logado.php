<?php
session_start();
?>
<!DOCTYPE html>
<html lang="pt">

<head>
  <link rel="stylesheet" href="css/font.css">
  <link href="https://fonts.googleapis.com/css2?family=Chakra+Petch&display=swap" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/mdb-ui-kit/6.4.1/mdb.min.css" rel="stylesheet">
  <meta charset="UTF-8">
  <link rel="stylesheet" href="css/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LoW</title>
</head>

<body>
  <div class="navbar">
    <span class="navbar-text">LoW</span>
    <div class="login">
      <a href="php/indexlogin.html" class="navbar-text"> <?php echo $_SESSION["nome"]; ?> </a>
    </div>
  </div>
  <div class="divfundo">
    <h3> We don't sell cars, <br> We sell experiences. <br> -Luxury on Wheels</h3>
    <video autoplay loop muted>
      <source src="src/0910.mp4" type="video/mp4">
      Seu navegador não suporta a reprodução de vídeos.
    </video>
  </div>

  <h1 class="">Cars</h1>
  <table class="table1">
    <tr>


      <td>
        <a href="html/ferrari/ferrari.html">
          <div class="ferrariimg divtable">
            <p class="txttable ferrari_font"> Ferrari </p>
          </div>
        </a>
      </td>



      <td>
        <a href="html/lambo/lambo.html">
          <div class="lamboimg divtable">
            <p class="txttable lambo_font"> Lamborghini </p>
          </div>
        </a>
      </td>



      <td>
        <a href="html/bmw/bmw.html">
          <div class="bmwimg divtable">
            <p class="txttable bmw_font"> BMW </p>
          </div>
        </a>
      </td>



      <td>
        <a href="html/mc/mc.html">
          <div class="mcimg divtable">
            <p style="font-size: 35px;" class="txttable mc_font"> McLaren </p>
          </div>
        </a>
      </td>



      <td>
        <a href="html/porche/porche.html">
          <div class="porcimg divtable">
            <p style="font-size: 30px;" class="txttable porche_font"> Porsche </p>
          </div>
        </a>
      </td>


    </tr>
  </table>

  <footer>
    &copy; 2023 UFE Group. Todos os direitos reservados.
  </footer>
</body>

</html>