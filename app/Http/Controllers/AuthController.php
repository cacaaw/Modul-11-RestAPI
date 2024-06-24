<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class AuthController extends Controller
{
    use HasApiTokens, Notifiable;

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'confirm_password' => 'required|same:password'
        ]);
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Ada kesalahan',
                'data' => $validator->errors()
            ]);
        }
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =
            $user->createToken('auth_token')->plainTextToken;
        $success['name'] = $user->name;
        return response()->json([
            'success' => true,
            'message' => 'Sukses register',
            'data' => $success
        ]);
    }

    public function login(Request $request)
    {
        if (Auth::attempt([
            'email' => $request->email,
            'password' => $request->password
        ])) {
            $user = Auth::user();
            $success['token'] =
                $user->createToken('auth_token')->plainTextToken;
            $success['name'] = $user->name;
            return response()->json([
                'success' => true,
                'message' => 'Sukses login',
                'data' => $success
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Gagal login',
                'data' => ''
            ]);
        }
    }
}
