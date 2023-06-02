<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Exception;
use Illuminate\Support\Facades\Log;

class PaymentController extends Controller
{
    // public function __construct()
    // {
    //     $this->middleware('auth.basic');
    // }

    public function makePayment(Request $request)
    {
        try {
            Log::info('Make Payment Request', [$request]);
            $toAccount = $request->get('toAccount');
            $fromAccount = $request->get('fromAccount');
            $transactionAmount = $request->get('transactionAmount');
            $narration = $request->get('narration');
            $serviceName = $request->get('serviceName');
            $senderName = $request->get('senderName');
            $receiverName = $request->get('receiverName');

            if (isset($toAccount) && isset($fromAccount) && isset($transactionAmount) && isset($narration) && isset($serviceName) && isset($senderName) && isset($receiverName)) {
                $transactionId = mt_rand(10000000, 99999999) . $senderName;
                $appVersion = '4.0.0+46';
                $checkoutMode = 'SHABELLEWALLET';
                $walletId = $fromAccount;
                $debitType = 'WALLET';
                $fromCurrency = 'UGX';
                $toCurrency = 'UGX';
                $fromAmount = $transactionAmount;
                $toAmount = $transactionAmount;
                $osType = 'ANDROID';
                $url = env('SHABELLE_GATEWAY') . '/processWalletPayment';
                $post_data = [
                    'toAccount' => $toAccount,
                    'fromAccount' => $fromAccount,
                    'transactionAmount' => $transactionAmount,
                    'narration' => $narration,
                    'serviceName' => $serviceName,
                    'senderName' => $senderName,
                    'receiverName' => $receiverName,
                    'transactionId' => $transactionId,
                    'appVersion' => $appVersion,
                    'checkoutMode' => $checkoutMode,
                    'debitType' => $debitType,
                    'fromCurrency' => $fromCurrency,
                    'toCurrency' => $toCurrency,
                    'fromAmount' => $fromAmount,
                    "phoneNumber"=>$fromAccount,
                    'toAmount' => $toAmount,
                    'osType' => $osType,
                    'walletId' => $walletId,
                    'location' => 'Ethiopia'
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
                    Log::info('Payment Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Payment Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactionId' => $result['transactionid'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Payment Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function authorizePayment(Request $request)
    {
        try {
            Log::info('Authorize Payment Request', [$request]);
            $otp = $request->get('otp');
            $walletId = $request->get('walletId');
            $tranType = $request->get('tranType');
            $tranReference = $request->get('tranReference');

            if (isset($otp) && isset($walletId) && isset($tranType) && isset($tranReference)) {
                $appVersion = '4.0.0+46';
                $checkoutMode = 'SHABELLEWALLET';
                $osType = 'ANDROID';
                $url = env('SHABELLE_GATEWAY') . '/authorizeWalletPayment';
                $post_data = [
                    'otp' => $otp,
                    'walletId' => $walletId,
                    'tranType' => $tranType,
                    'tranReference' => $tranReference,
                    'appVersion' => $appVersion,
                    'checkoutMode' => $checkoutMode,
                    'osType' => $osType,
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
                    Log::info('Authorize Payment Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Authorize Payment Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactionId' => $result['transactionid'] ?? '',
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Authorize Payment Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function getTransactions(Request $request)
    {
        try {
            Log::info('Get Transactions Request', [$request]);
            $username = $request->get('username');
            $startDate = $request->get('startDate');
            $endDate = $request->get('endDate');

            if (isset($username) && isset($startDate) && isset($endDate)) {
                $url = env('SHABELLE_GATEWAY') . '/getClientTransactionStatement';
                $post_data = [
                    'username' => $username,
                    'startDate' => $startDate,
                    'endDate' => $endDate,
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
                    Log::info('Get Transactions Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Get Transactions Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactions' => $result['appTransactions'] ?? [],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Get Transactions Exception Error', [$e->getMessage()]);
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
                    "creation_date" => date('Y-m-d'),
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
