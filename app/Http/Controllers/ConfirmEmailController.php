<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Mail\Confirm;

class ConfirmEmailController extends Controller
{
    public function showConfirmForm()
    {
        return view('confirm');
    }

    public function generateLink(Request $request)
    {
    	$this->validator($request->all())->validate();

    	$timeNow = time();
    	$emailAddr = $request->email;

    	$token = encrypt($timeNow . '+' . $emailAddr);

    	\Mail::to($request->email)->send(new Confirm($token));

        session()->flash('message', 'Registration link sent.');

    	return redirect('/');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'email' => 'required|string|email|max:255|unique:users',
        ]);
    }
}
