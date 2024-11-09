<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login & Signup Form</title>
    <link rel="stylesheet" href="style.css" />
</head>

<body>


    <section class="wrapper">

        <div class="form signup">
            <header>Signup</header>
            <form action="signup.php" method="post">
                <input type="text" name="username" placeholder="Full name" required />
                <input type="email" name="useremail" placeholder="Email address" required />
                <input type="password" name="userpass" placeholder="Password" required />
                <div class="checkbox">
                    <input type="checkbox" id="signupCheck" required />
                    <label for="signupCheck">I accept all terms & conditions</label>
                </div>
                <input type="submit" value="Signup" />
            </form>
        </div>


        <div class="form login">
            <header>Login</header>
            <form action="login.php" method="post">
                <input type="text" name="useremail" placeholder="Email address" required />
                <input type="password" name="userpass" placeholder="Password" required />
                <a href="#">Forgot password?</a>
                <input type="submit" value="Login" />
            </form>
        </div>

    </section>

    <script>
        const wrapper = document.querySelector(".wrapper"),
            signupHeader = document.querySelector(".signup header"),
            loginHeader = document.querySelector(".login header");

        loginHeader.addEventListener("click", () => {
            wrapper.classList.add("active");
        });
        signupHeader.addEventListener("click", () => {
            wrapper.classList.remove("active");
        });
    </script>
</body>

</html>