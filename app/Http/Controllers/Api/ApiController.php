<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        $validateUser = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
        ]);
        if ($validateUser->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'validation error',
                    'error' => $validateUser->errors()
                ],
                401,
            );
        }
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken("API TOKEN")->plainTextToken;
        // $credentials = $request->only('email', 'password');
        // Auth::attempt($credentials);
        // $request->session()->regenerate();

        return response()->json([
            'status' => true,
            'message' => 'User Created Successfully',
            'user' => $user,
            'token' => $token
        ]);
    }

    public function login(Request $request)
    {
        $validateUser = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);
        if ($validateUser->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'validation error',
                    'error' => $validateUser->errors()
                ],
                401,
            );
        }
        $user = User::where('email', $request['email'])->firstOrFail();
        $token = $user->createToken("API TOKEN")->plainTextToken;

        if (Auth::attempt($request->only(['email', 'password']))) {
            // $request->session()->regenerate();
            return response()->json([
                'status' => true,
                'message' => 'User Logged In Successfully',
                'user' => $user,
                'token' => $token
            ]);
        } else {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Email & password does not match with our record',
                ],
                401,
            );
        }
    }
}
