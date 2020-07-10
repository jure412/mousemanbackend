<?php

    namespace App\Http\Controllers;

    use App\User;
    use Illuminate\Http\Request;
    // use Illuminate\Support\Facades\Hash;
    // use Illuminate\Support\Facades\Validator;
    use Validator, DB, Hash, Mail, Auth;
    use Illuminate\Support\Facades\Password;
    use Illuminate\Mail\Message;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;

    class AuthController extends Controller
    {
        public function authenticate(Request $request)
        {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:255|',
                'password' => 'required|string|min:6',
            ]);

            if($validator->fails()){
                    return response()->json($validator->errors(), 400);
            }
            $credentials = $request->only('email', 'password');

            $credentials['is_verified'] = 1;
            try {
                if (! $token = JWTAuth::attempt($credentials)) {
                    return response()->json(['email' => 'We cant find an account with this credentials. Please make sure you entered the right information and you have verified your email address.'], 400);
                }
                
            } catch (JWTException $e) {
                
                return response()->json(['email' => 'could not create token'], 500);

            }
            $user = Auth::user();

            return response()->json(compact('token', 'user'));
        }

        public function register(Request $request)
        {
                $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:6|confirmed',
            ]);

            if($validator->fails()){
                    return response()->json($validator->errors(), 400);
            }

            $name = $request->name;
            $email = $request->email;
            $password = $request->password;

            $user = User::create([
                'name' => $name,
                'email' => $email,
                'password' => Hash::make($password),
            ]);

            $verification_code = str_random(30); //Generate verification code
            DB::table('user_verifications')->insert(['user_id'=>$user->id,'token'=>$verification_code]);

            $subject = "Please verify your email address.";

            Mail::send('verify', ['name' => $name, 'verification_code' => $verification_code],
                function($mail) use ($email, $name, $subject){
                    $mail->from('jur3curk@gmail.com', 'My app');
                    $mail->to($email, $name);
                    $mail->subject($subject);
                });

            return response()->json(compact('subject'),201);
        }

        public function loginGoogle(Request $request)
        {
                $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255',
            ]);

            if($validator->fails()){
                    return response()->json($validator->errors(), 400);
            }

            $name = $request->name;
            $email = $request->email;

            $credentials = ['name' => $name, 'email' => $email, 'is_verified' => 1, 'password' => time()];
            if (User::where('email', '=', $email)->exists()) {
                $user = User::where('email', '=', $email)->first();
                try {
                    if (! $token = JWTAuth::fromUser($user)) {
                        return response()->json(['email' => 'We cant find an account with this credentials. Please make sure you entered the right information and you have verified your email address.'], 400);
                    }
                } catch (JWTException $e) {   
                    return response()->json(['email' => 'could not create token'], 500);
                }
                return response()->json(compact('token', 'user'));
            }
            $user = User::create($credentials);
            try {
                if (! $token = JWTAuth::fromUser($user)) {
                    return response()->json(['email' => 'We cant find an account with this credentials. Please make sure you entered the right information and you have verified your email address.'], 400);
                }
            } catch (JWTException $e) {
                return response()->json(['email' => 'could not create token'], 500);
            }
            return response()->json(compact('token', 'user'));
        }


        public function verifyUser($verification_code)
        {
            $check = DB::table('user_verifications')->where('token',$verification_code)->first();
            if(!is_null($check)){
                $user = User::find($check->user_id);
                if($user->is_verified == 1){
                    return response()->json([
                        'message'=> 'Account already verified..'
                    ]);
                }
                $user->update(['is_verified' => 1]);
                DB::table('user_verifications')->where('token',$verification_code)->delete();
                $success= 'You have successfully verified your email address.';
                // return response()->json(compact('success'));
                return redirect()->to('http://localhost:3000/login');
            }
            $error =  "Verification code is invalid.";
            return response()->json(compact('success'));

        }
        public function recover(Request $request)
        {
            $user = User::where('email', $request->email)->first();
            if (!$user) {
                $error_message = "Your email address was not found.";
                return response()->json(compact('error_message'), 401);
            }

            try {
                Password::sendResetLink($request->only('email'), function (Message $message) {
                    $message->subject('Your Password Reset Link');
                });

            } catch (\Exception $e) {
                //Return with error
                $error_message = $e->getMessage();
                return response()->json(['success' => false, 'error' => $error_message], 401);
            }

            $success = 'A reset email has been sent! Please check your email.';

            // return response()->json(compact('sucess'));
            return response()->json(compact('user'));
        }

        public function getAuthenticatedUser()
            {
                    try {

                            if (! $user = JWTAuth::parseToken()->authenticate()) {
                                    return response()->json(['user_not_found'], 404);
                            }

                    } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

                            return response()->json(['token_expired'], $e->getStatusCode());

                    } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

                            return response()->json(['token_invalid'], $e->getStatusCode());

                    } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

                            return response()->json(['token_absent'], $e->getStatusCode());

                    }
                    $token = JWTAuth::getToken();

                    if(!$token){
                        throw new BadRequestHtttpException('Token not provided');
                    }
                    try{
                        $token = JWTAuth::refresh($token);
                    }catch(TokenInvalidException $e){
                        throw new AccessDeniedHttpException('The token is invalid');
                    }
            

                    return response()->json(compact('user', 'token'));
            }
        
        public function logout(Request $request) {
            $this->validate($request, ['token' => 'required']);
            try {
                JWTAuth::invalidate($request->input('token'));
                return response()->json(['message'=> "You have successfully logged out."]);
            } catch (JWTException $e) {
                // something went wrong whilst attempting to encode the token
                return response()->json(['error' => 'Failed to logout, please try again.'], 500);
            }
        }
// tukaj bomo v protected routi checkirali ce token obstaja in ce obstaja naj se refresha
        public function refreshToken(){
            $token = JWTAuth::getToken();
            $user = JWTAuth::toUser($token);
            if(!$token){
                throw new BadRequestHtttpException('Token not provided');
            }
            try{
                $token = JWTAuth::refresh($token);
            }catch(TokenInvalidException $e){
                throw new AccessDeniedHttpException('The token is invalid');
            }
            
            return response()->json(compact('token', 'user'));
        }
        public function helo(){
            $user = User::where('email', '=', 'jani@gmail.com')->first();
            return response()->json(compact('user'));
         }
    }