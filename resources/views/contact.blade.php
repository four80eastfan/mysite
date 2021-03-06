@extends('layouts.app')

@section('css')
    <link href="{{ asset('css/contact_page.css') }}" rel="stylesheet">
@endsection

@section('script')
    <!-- <script src="https://www.google.com/recaptcha/api.js" async defer></script> -->
@endsection

@section('content')
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">Contact</div>
                <div class="panel-body">
                    <form class="form-horizontal" role="form" method="POST" action="{{ route('contact') }}">
                        {{ csrf_field() }}

                        <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
                            <label for="name" class="col-md-4 control-label">Name</label>

                            <div class="col-md-6">
                                <input id="name" type="text" class="form-control" name="name" value="{{ old('name') }}" required autofocus>

                                @if ($errors->has('name'))
                                    <span class="help-block">
                                        <strong>{{ $errors->first('name') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                            <label for="email" class="col-md-4 control-label">E-Mail Address</label>

                            <div class="col-md-6">
                                <input id="email" type="email" class="form-control" name="email" value="{{ old('email') }}" required>

                                @if ($errors->has('email'))
                                    <span class="help-block">
                                        <strong>{{ $errors->first('email') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>

                        <div class="form-group{{ $errors->has('message') ? ' has-error' : '' }}">
                            <label for="message" class="col-md-4 control-label">Message</label>

                            <div class="col-md-6">
                                <textarea id="message" type="text" class="form-control" name="message" rows="3" value="{{ old('message') }}" required>Contact form is temporarily disabled until I have time to integrate the reCAPTCHA. Sorry for the inconvenience...</textarea>

                                @if ($errors->has('message'))
                                    <span class="help-block">
                                        <strong>{{ $errors->first('message') }}</strong>
                                    </span>
                                @endif
                            </div>
                        </div>
                        
                        <!-- <div class="g-recaptcha col-md-6" data-sitekey="6LfVdLgUAAAAADZeYm6yKHM8p8ls5G8WyxcZtdMC"></div>
                        <br/> -->

                        <div class="form-group">
                            <div class="col-md-6 col-md-offset-4">
                                <button type="submit" class="btn btn-primary" disabled="true">
                                    Send Message
                                </button>
                            </div>
                        </div>

                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
