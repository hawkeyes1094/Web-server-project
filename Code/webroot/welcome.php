<html>
<body>

<p>Welcome <?php echo $_GET["name"]; ?> from <?php echo getenv("REMOTE_HOST"); ?></p>

<p>Your email address is: <?php echo $_GET["email"]; ?><p>

<p> GET variable data - <br />
    <?php
    foreach ($_GET as $param_name => $param_val) {
        echo "Param: $param_name; Value: $param_val<br />\n";
    }
    ?>
</p>

</body>
<footer>
    <p><a href="welcome.html">Welcome/GET page</a></p>
    <p><a href="index.html">Home Page</a></p>
</footer>
</html>