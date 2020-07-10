<?php

    namespace App;

    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Illuminate\Contracts\Auth\MustVerifyEmail;
    use Tymon\JWTAuth\Contracts\JWTSubject;
    use App\Notifications\PasswordResetNotification;

    class User extends Authenticatable implements JWTSubject, MustVerifyEmail
    {
        use Notifiable;

        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password', 'is_verified'
        ];

        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];


        public function getJWTIdentifier()
        {
            return $this->getKey();
        }
        public function getJWTCustomClaims()
        {
            return [];
        }

        public function sendPasswordResetNotification($token)
        {
            $this->notify(new PasswordResetNotification($token));
        }
    }