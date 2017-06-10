@extends('layouts.app')

@section('css')
    <link href="{{ asset('css/confirm_page.css') }}" rel="stylesheet">
@endsection

@section('content')
<div class="container">
    @if($flash = session('message'))
        <div id="flash-message" class="alert alert-danger" role="alert">
            {{ $flash }}
        </div>
    @endif
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">Confirm E-Mail Address</div>
                <div class="panel-body">
                    <form class="form-horizontal" role="form" method="POST" action="{{ route('confirm') }}">
                        {{ csrf_field() }}

                        <p>Please note that the registration link will expire 30 minutes after it is sent. Thank you.</p>

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

                        <div class="form-group">
                            <div class="col-md-6 col-md-offset-4">
                                <button type="submit" class="btn btn-primary">
                                    Send Registration Link
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
