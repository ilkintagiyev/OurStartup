<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string|min:3',
            'surname' => 'required|string|min:3',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string',

        ]);

       $user = User::create([
                    'name'      => $fields['name'],
                    'surname'   => $fields['surname'],
                    'email'     => $fields['email'],
                    'password'  => bcrypt($fields['password']),
                ]);
        $token = $user->createToken('myappToken')->plainTextToken;

        $response = [
            'token' => $token,
            'user' => $user

        ];

        Auth()->login($user);
        return response($response, 201);


    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required|string|exists:users,email',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $fields['email'])->first();

        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message' => 'Invalid Credentials'
            ], 401);
        }

        $token = $user->createToken('myappToken')->plainTextToken;
        $response = [
            'token' => $token,
            'user' => $user

        ];

        if(Auth()->attempt($fields))
        {
             session()->regenerate();
             return response($response, 201);
        }
    }
}
