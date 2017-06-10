<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Mail\Contact;

class ContactController extends Controller
{
    public function showContactForm()
    {
        return view('contact');
    }

    public function sendContactForm(Request $request)
    {
    	$this->validator($request->all())->validate();

		\Mail::to('matthew.akkerman@gmail.com')->send(new Contact($request));

		session()->flash('message', 'Message sent. Thank you!');

    	return redirect('/');
    }

    /**
     * Get a validator for an incoming rcontact request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255',
            'message' => 'required|string|min:10',
        ]);
    }
}
