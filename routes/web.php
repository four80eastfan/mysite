<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

//use \App\Http\Middleware\CheckToken;

Route::get('/', function () {
    return view('welcome');
})->name('welcome');

#Auth::routes();

// Authentication Routes...
Route::get('login', 'Auth\LoginController@showLoginForm')->name('login');
Route::post('login', 'Auth\LoginController@login');
Route::post('logout', 'Auth\LoginController@logout')->name('logout');

// Registration Routes...
#$this->get('register', 'Auth\RegisterController@showRegistrationForm')->name('register');
Route::get('/register', function () {
	return redirect('confirm');
})->name('register');
Route::post('register', 'Auth\RegisterController@register');
Route::get('/register/{token}', 'Auth\RegisterController@checkToken');

// Password Reset Routes...
Route::get('password/reset', 'Auth\ForgotPasswordController@showLinkRequestForm')->name('password.request');
Route::post('password/email', 'Auth\ForgotPasswordController@sendResetLinkEmail')->name('password.email');
Route::get('password/reset/{token}', 'Auth\ResetPasswordController@showResetForm')->name('password.reset');
Route::post('password/reset', 'Auth\ResetPasswordController@reset');

/*Route::get('/register/{token}', function() {
	//
})->middleware('token');*/

Route::get('/home', 'HomeController@index')->name('home');

Route::get('/confirm', 'ConfirmEmailController@showConfirmForm')->name('confirm');
Route::post('/confirm', 'ConfirmEmailController@generateLink');

Route::get('/contact', 'ContactController@showContactForm');
Route::post('/contact', 'ContactController@sendContactForm')->name('contact');
#Route::get('/contact', 'HomeController@index'); # temp fix for spam

Route::get('/blog', 'BlogController@showBlog')->name('blog');

Route::get('/test', 'TestController@showTestPage');
