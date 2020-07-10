<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:api')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::post('register', 'AuthController@register');
Route::post('loginGoogle', 'AuthController@loginGoogle');
Route::post('login', 'AuthController@authenticate');
// Route::get('user', 'AuthController@getAuthenticatedUser');

Route::post('forgotpassword', 'AuthController@recover');
Route::post('/password/email', 'ForgotPasswordController@sendResetLinkEmail');
Route::post('/password/reset', 'ResetPasswordController@reset');

Route::group(['middleware' => ['jwt.auth']], function() {
    
    Route::post('logout', 'AuthController@logout');
    Route::get('user', 'AuthController@getAuthenticatedUser');
    Route::get('refresh', 'AuthController@refreshToken');
    // Route::get('closed', 'DataController@closed');
});