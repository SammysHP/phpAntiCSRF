<?php
include('AntiCSRF.php');

if (isset($_POST['submit']) || isset($_GET['get'])) {
    AntiCSRF::verifyOrFail();
    echo "CSRF check ok!";
}
?>

<form method="POST">
    <?php $csrf = new AntiCSRF(); echo $csrf->getPostString(); ?>
    <button class="button" type="submit" name="submit">POST</button>
</form>

<a href="?get=true&<?php $csrf = new AntiCSRF(); echo $csrf->getGetString(); ?>">GET</a>
