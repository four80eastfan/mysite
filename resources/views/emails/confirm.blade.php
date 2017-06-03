@component('mail::message')
# Howdy!
<br>

You're less than a minute away from completing your registration. Please click on the button below in order in order to continue signing up.

@component('mail::button', ['url' => $link])
Register
@endcomponent

Thanks,<br>
{{ config('app.name') }}
@endcomponent
