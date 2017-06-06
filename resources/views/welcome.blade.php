<!doctype html>
<html lang="{{ config('app.locale') }}">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>MattAkkerman.com</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Raleway:100,600" rel="stylesheet" type="text/css">
        <link href="https://fonts.googleapis.com/css?family=Lobster" rel="stylesheet">

        <!-- Styles -->
        <style>
            html, body {
                /*background-color: #fff;*/
                color: #636b6f;
                font-family: 'Raleway', sans-serif;
                font-weight: 100;
                height: 100vh;
                margin: 0;
            }

            .container {
                /* The image used */
                background-image: url('./images/fog.png');

                /* Full height */
                height: 100%; 

                /* Center and scale the image nicely */
                background-position: center;
                background-repeat: no-repeat;
                background-size: cover;
            }

            .full-height {
                height: 100vh;
            }

            .flex-center {
                align-items: center;
                display: flex;
                justify-content: center;
            }

            .position-ref {
                position: relative;
            }

            .top-right {
                position: absolute;
                right: 10px;
                top: 18px;
            }

            .content {
                text-align: center;
            }

            .title {
                font-size: 84px;
                font-family: 'Lobster', cursive;
            }

            .links > a {
                color: black;
                padding: 0 25px;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: .1rem;
                text-decoration: none;
                text-transform: uppercase;
            }

            .m-b-md {
                margin-bottom: 30px;
            }

            .alert {
              padding: 15px;
              margin-bottom: 22px;
              border: 1px solid transparent;
              border-radius: 4px;
              font-weight: bold;
            }

            .alert-success {
              background-color: #dff0d8;
              border-color: #d6e9c6;
              color: #3c763d;
            }

            #flash-message {
                position: absolute;
                top: 20px;
                z-index: 10;
                animation: flash-message 7s forwards;
            }

            @keyframes flash-message {
                0%   {opacity: 1;}
                100% {opacity: 0; display:none;}
            }

            @media (max-width: 550px) {
                .title {
                    font-size: 40px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="flex-center position-ref full-height">
                @if (Route::has('login'))
                    <div class="top-right links">
                        @if (Auth::check())
                            <a href="{{ url('/home') }}">Home</a>
                        @else
                            <a href="{{ url('/login') }}">Login</a>
                            <a href="{{ url('/confirm') }}">Register</a>
                        @endif
                    </div>
                @endif
                @if($flash = session('message'))
                    <div id="flash-message" class="alert alert-success" role="alert">
                        {{ $flash }}
                    </div>
                @endif
                <div class="content">
                    <div class="title m-b-md">
                        MattAkkerman
                    </div>

                    <div class="links">
                        <a href="{{ url('/blog') }}">Blog</a>
                        <a href="{{ url('/contact') }}">Contact</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>
