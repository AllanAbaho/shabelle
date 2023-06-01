<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Exception;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    // public function __construct()
    // {
    //     $this->middleware('auth.basic');
    // }

    public function login(Request $request)
    {
        try {
            Log::info('Login User Request', [$request]);
            $phone = $request->get('phone');
            $pin = $request->get('pin');
            if (isset($phone) && isset($pin)) {
                $pin = self::encryptPin($pin);
                $url = env('SHABELLE_GATEWAY') . '/login';
                $post_data = [
                    'username' => $phone,
                    'pin' => $pin
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Login User Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Login User Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'phone' => $result['customer_phone'],
                    'name' => $result['customer_name'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Login User Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function register(Request $request)
    {
        try {
            Log::info('Register User Request', [$request]);
            $name = $request->get('name');
            $phone = $request->get('phone');
            $pin = $request->get('pin');
            if (isset($phone) && isset($pin)) {
                $pin = self::encryptPin($pin);
                $url = env('SHABELLE_GATEWAY') . '/newUserRegistration';
                $post_data = [
                    'fullName' => $name,
                    'phone' => $phone,
                    'pin' => $pin,
                    "appVersion" => "4.0.0+46",
                    "checkoutMode" => "SHABELLEWALLET",
                    "osType" => "ANDROID",
                    "creation_date"=> date('Y-m-d'),
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Register User Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Register User Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Register User Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function validateAccount(Request $request)
    {
        try {
            Log::info('Validate Account Request', [$request]);
            $walletId = $request->get('walletId');
            if (isset($walletId)) {
                $url = env('SHABELLE_GATEWAY') . '/queryAccountDetails';
                $post_data = [
                    'username' => $walletId,
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Validate Account Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Validate Account Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'walletId' => $result['wallet_id'] ?? '',
                    'name' => $result['name'] ?? '',
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function queryWalletBalance(Request $request)
    {
        try {
            Log::info('Query Wallet Balance Request', [$request]);
            $username = $request->get('username');
            if (isset($username)) {
                $url = env('SHABELLE_GATEWAY') . '/QueryWalletBalance';
                $post_data = [
                    'username' => $username,
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Query Wallet Balance Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Query Wallet Balance Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'balance' => str_replace(',', '', $result['balance'])
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }


    public function encryptPin($pin)
    {
        $vendorSecretKey = "CZKGZ9JO2T4OOPQOWET2";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $randomString = random_bytes(16);
        $initializationVector = substr(bin2hex($randomString), 0, 16);
        $cipher = "aes-256-cbc";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $rawCipherText = openssl_encrypt($pin, $cipher, $encryptionKey, OPENSSL_RAW_DATA, $initializationVector);
        $encryption = base64_encode($rawCipherText);

        return $initializationVector . $encryption;
    }
}
