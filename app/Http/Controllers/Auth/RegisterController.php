<?php

namespace App\Http\Controllers\Auth;

use App\User;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
        //$this->middleware('token');
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
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);
    }

    public function checkToken($token = null)
    {
        try
        {
            $decrypted = decrypt($token);
        }
        catch(\Exception $e)
        {
            return redirect('confirm');
        }

        $exploded = explode('+', $decrypted, 2);

        $timePast = $exploded[0];

        $email = $exploded[1];

        $timeNow = time();

        if((intval($timePast) + 1800) < $timeNow) {
            session()->flash('message', 'Link has expired.');
            return redirect('confirm');
        } 
        else
        {
            return view('auth.register', ['token' => $token, 'email' => $email, 'time' => $timePast]);
            //return view('auth.register', ['email' => $email]);
            //return view('auth.register');
        }

        //return view('test', ['test' => $exploded[1]]);
    }
}
