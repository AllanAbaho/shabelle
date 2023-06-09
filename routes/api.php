<?php

use Illuminate\Support\Facades\Route;

Route::group(array('prefix' => '/v1'), function () {
    Route::post('/login', 'App\Http\Controllers\AuthController@login');
    Route::post('/register', 'App\Http\Controllers\AuthController@register');
    Route::post('/queryWalletBalance', 'App\Http\Controllers\AuthController@queryWalletBalance');
    Route::post('/make-payment', 'App\Http\Controllers\PaymentController@makePayment');
    Route::post('/validateAccount', 'App\Http\Controllers\AuthController@validateAccount');
    Route::post('/authorizePayment', 'App\Http\Controllers\PaymentController@authorizePayment');
    Route::post('/processUtilityPayment', 'App\Http\Controllers\PaymentController@processUtilityPayment');
    Route::post('/getTransactions', 'App\Http\Controllers\PaymentController@getTransactions');
    Route::post('/changePin', 'App\Http\Controllers\AuthController@changePin');
    Route::post('/checkStatus', 'App\Http\Controllers\PaymentController@checkStatus');
    Route::post('/validateMobileMoney', 'App\Http\Controllers\PaymentController@validateMobileMoney');
    Route::post('/validateBankAccount', 'App\Http\Controllers\PaymentController@validateBankAccount');
    Route::post('/validatePayBillAccount', 'App\Http\Controllers\PaymentController@validatePayBillAccount');
});
