@component('mail::message')
# A message for you!

New message from {{ $data->name }} at {{ $data->email }}.

{{ $data->message }}

@endcomponent
