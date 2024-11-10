<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        /* Basic styling for the page */
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(45deg, #170c46, #fff, #170c46);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }

        .container {
            background-color: #fff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            width: 300px;
        }

        h1 {
            color: #333;
            margin-bottom: 20px;
        }

        a {
            text-decoration: none;
            color: white;
            background-color: #170c46;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }

        a:hover {
            background-color: #fff;
            color : #170c46;
        }
    </style>
</head>

<body>

    <div class="container">
        <h1>Welcome! Students </h1>
        <p>You are successfully logged in.</p>
        <br>
        <a href="logout.php">Logout</a>
    </div>

</body>

</html>
