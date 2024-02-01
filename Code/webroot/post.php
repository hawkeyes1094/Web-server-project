<html>
    <body>
        <div>
            <h2>LOGIN SUCCESSFUL</h2>
        </div>
        <br />
        <div>
            <p>Welcome <?php echo $_POST["email"]; ?></p>
        </div>
        <br />
        <div>
            <p> Your password's BCRYPT hash is <?php echo password_hash($_POST["password"], PASSWORD_BCRYPT); ?></p>
        </div>
    </body>
    <footer>
        <p><a href="post.html">POST page</a></p>
        <p><a href="index.html">Home Page</a></p>
    </footer>
</html>