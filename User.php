<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Laravel\Jetstream\HasProfilePhoto;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Storage;
use Illuminate\Database\Eloquent\SoftDeletes;
use DB;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Role;
use App\Models\UserRequest;

class User extends Authenticatable
{
    use HasApiTokens,HasRoles;
    use HasProfilePhoto;
    use TwoFactorAuthenticatable;
    use HasFactory, Notifiable,HasApiTokens, HasRoles, SoftDeletes;
    // use HasFactory;
    // use Notifiable;


    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'first_name',
        'last_name',
        'phone',
        'name',
        'email',
        'password',
        "is_active",
        "unique_code",
        "country_code",
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_recovery_codes',
        'two_factor_secret',
        'otp'
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * The accessors to append to the model's array form.
     *
     * @var array
     */
    // protected $appends = [
    //     'profile_photo_url',
    // ];


   /**
   * Using multiple guards.
   * define guard name other than 'web' guard which is defualt guard
   */
   protected $guard_name = 'api';

   public function rulesForgotPassword($data){
        $validator = Validator::make($data,[
            "username"=>["required","email",function($attribute,$value,$fail){
                $validUsername = User::whereHas('roles', function( $query) {
                    // return $query->where('name', 'Patient');
                 })->where("email","like","%".$value."%")
                //  ->whereNotNull("email_verified_at")
                 ->count();
                    if($validUsername ==0) {
                        $fail(trans("messages.invalidUsername"));
                    }
                    // else if($validUsername->email_verified_at ==null){
                    //     $fail(trans("messages.emailNotVerified"));
                    // }
            }]
        ]);
        return $validator;
    }
    public function rulesdeleteUser($data){
        $validator = Validator::make($data, [
            "user_id" => ["required", "integer",
              function ($attribute, $value, $fail) {
                if (User::whereId($value)->whereHas('roles', function ($query) {
                    $query->where('name','!=', 'Super-Admin');
                    })->count() ==0) {
                    $fail(trans("messages.userNotFound"));
                }
              },
            ],
          ]);
        return $validator;
    }
    public function rulesPermanentDelete($data){
        $validator = Validator::make($data, [
            "user_id" => ["required", "integer",
              function ($attribute, $value, $fail) {
                if (User::whereId($value)->withTrashed()->whereHas('roles', function ($query) {
                    $query->where('name','!=', 'Super-Admin');
                    })->count() ==0) {
                    $fail(trans("messages.userNotFound"));
                }
              },
            ],
          ]);
        return $validator;
    }
    public function rulesContactUs($data){
        $validator = Validator::make($data,[
            "name"=>"required",
            "email"=>"required|email",
            "message"=>"required",
        ]);
        return $validator;
    }
    public function rulesRegister($data){
        $validator = Validator::make($data,[
            "user_type"=>["required",Rule::in(['Patient', 'Doctor','Clinic'])],
            "name"=>"required|string",
            "email"=>"required|email|unique:users",
            "password"=>"min:6|required|required_with:password_confirmation|same:password_confirmation",
            "password_confirmation"=>"min:6",
        ]);
        return $validator;
    }
    public function rulesLogin($data){
        $validator = Validator::make($data,[
            "email"=>"required|email",
            "password"=>"required",
            "role"=>["nullable",function ($attribute, $value, $fail) use ($data) {
                if(!User::where('email', '=', $data['username'])->count() > 0){       // if already register not check for role
                  if ($value == 'Super-Admin') {    //if anyone attempt register with Super Admin role, not permitted
                    $fail('The '.$attribute.' '.$value.' is reserved');
                  }

                  $role_exists = Role::where('name', $value)->first();
                  if(is_null($role_exists)){                                  // role required for register
                      $fail('The '.$attribute.' '.$value.' does not exists');
                  }
                }
              },],
        ]);
        return $validator;
    }
    public function rulesUploadPicture($data){
        $validator = Validator::make($data,[
            "image"=>"required|image",
        ]);
        return $validator;
    }
    public function rulesPersonalInfo($request){

        $validator = Validator::make($request->all(),[
            "salutation"=>"required|in:0,1",
            "first_name"=>"required|alpha",
            "middle_name"=>"sometimes",
            "last_name"=>"alpha",
            "country_code"=>"required|between:1,6",
            "phone"=>["required","digits_between:7,12",function($attribute,$value,$fail) use($request) {
               $number_exists =  User::where([["phone",$value],["country_code",$request->country_code],["id","!=",$request->user()->id]])
                ->count();
                if($number_exists){
                    $fail(trans("messages.phoneTaken"));
                }
            }],
            "mobile"=>["required","digits_between:7,12",function($attribute,$value,$fail) use($request) {
                $number_exists =  User::where([["mobile",$value],["country_code",$request->country_code],["id","!=",$request->user()->id]])
                 ->count();
                 if($number_exists){
                     $fail(trans("messages.mobileTaken"));
                 }
             }],
            // "required|digits:10|unique:users,phone,".$request->user()->id,
            "office_address"=>"sometimes|array",
            "week_off"=>"sometimes|nullable",
            "correspondence_address"=>"sometimes|array",
            // "email"=>"required|unique:users,email,".$request->user()->id,
        ]);
        return $validator;
    }
    public function rulesProfessionalInfo($request){
        $messages = [
            "registration.*.registration_number.required"=>"The registration number field is required.",
            "registration.*.registration_authority.required"=>"The registration authority field is required.",
            "registration.*.year.required"=>"The registration year is required.",
            "registration.*.document.required"=>"The registration document is required.",
            "education.*.qualification.required"=>"The education qualification field is required.",
            "education.*.college_university.required"=>"The college university field is required.",
            "education.*.year.required"=>"The education year is required.",
            "education.*.document.required"=>"The education document is required.",
        ];
        $validator = Validator::make($request->all(),[

            "registration"=>"present|array",
            "registration.*.registration_number"=>"required|string",
            "registration.*.registration_authority"=>"required",
            "registration.*.year"=>"required|digits:4",
            "registration.*.document"=>[function($attribute, $value, $fail) use($request){
                $index = str_replace('.document','',substr($attribute,13));
                if(! isset($request['registration'][$index]['id'])){
                    if(!$value){
                        $fail("Please provide valid registration document");
                    }
                }
            }],
            "registration.*.year"=>"required|digits:4|integer|min:1901|max:".date('Y'),
            "education"=>"present|array",
            "education.*.qualification"=>"required|string",
            "education.*.college_university"=>"required",
            "education.*.year"=>"required|digits:4",
            "education.*.document"=>[function($attribute, $value, $fail) use($request){
                $index = str_replace('.document','',substr($attribute,11));
                if(! isset($request['education'][$index]['id'])){
                    if(!$value){
                        $fail("Please provide valid education document");
                    }
                }
            }],
            "education.*.year"=>"required|digits:4|integer|min:1901|max:".date('Y'),
            "role"=>"sometimes|string",
            "clinic_name"=>"sometimes|string",
            "address_line1"=>"sometimes|string",
            "address_line2"=>"sometimes|string",
            "city"=>"sometimes|string",
            "state"=>"sometimes|string",
            "country"=>"sometimes|string",
            "zipcode"=>"sometimes|integer",
            "duration"=>"sometimes|integer",
            "reference"=>"sometimes|string",
            "linkedin_profile"=>"sometimes|string",
            "reference_email"=>"sometimes|email",
            "reference_phone"=>"sometimes|string",
            "speciality.*"=>"required|array",
        ],$messages);

        return $validator;
    }

    public function rulesBusinessInfo($request){
      $messages = [
      ];
      $validator = Validator::make($request->all(),[
          "clinic_name"=>"required|regex:/^[a-zA-Z\s]+$/",
          "clinic_email"=>"required|email",
          "clinic_phone_number"=>"required|integer",
          "tax_number"=>"required|regex:/^(?!-)[0-9-a-zA-Z]+$/",
          "registration_authority"=>"required|string",
          "registration_number"=>"required|json",
          "address_line"=>"required|string",
          "city"=>"required",
          "state"=>"required",
          "country"=>"required",
          "postcode"=>"required|integer",
          // "file"=>"required",
          "payment.account_no"=>"required|integer",
          "payment.card_holder_name"=>"required|string",
          "payment.bank_name"=>"required|string",
          "payment.sort_code"=>"required|integer",
          "payment.swift_code"=>"required|string",
          "payment.is_primary_acc"=>"required|integer",
      ],$messages);

      return $validator;
  }

  public function rulesVisibleProfle($request){
    $messages = [
    ];
    $validator = Validator::make($request->all(),[
        "introduction_title"=>"required|alpha",
        "professional_career_desc"=>"required|string",
    ],$messages);

    return $validator;
  }

  public function rulesClinicPersonalInfo($request){
    $messages = [
    ];
    $validator = Validator::make($request->all(),[
      "clinic_name"=>"required|alpha",
      "email"=>"required|email",
      "country_code"=>"required|between:1,4",
      "phone"=>"required|integer",
      "phone"=>["required","digits_between:7,12",function($attribute,$value,$fail) use($request) {
        $number_exists =  User::where([["phone",$value],["country_code",$request->country_code],["id","!=",$request->user()->id]])
         ->count();
         if($number_exists){
             $fail(trans("messages.phoneTaken"));
         }
     }],
      "active_since"=>"required",
      "week_off"=>"required|json",
      "linkedin_profile"=>"required|string",
      "active_licence_no"=>"required|integer",
      "edit_clinic_id"=>"required|integer",
    ],$messages);

    return $validator;
  }

    public function rulesareCatSubTreatments($request){
        $validator = Validator::make($request->all(),[
            "type"=>"required|in:1,2,3,4",
            "area_id"=>"required_if:type,2,3,4",
            "category_id"=>"required_if:type,3,4",
            "sub_category_id"=>"required_if:type,4",
        ]);
        return $validator;
    }
    public function rulesSaveClinic($request){

        $validator = Validator::make($request->all(),[
            "name"=>"required|string",
            "email"=>"required|email|unique:users,email",
            "phone"=>"required|unique:users,phone",
            "linkedin_profile"=>"required",
        ]);
        return $validator;
    }
    public function rulesRemoveDoctor($data){
        $validator = Validator::make($data, [
            "user_id" => ["required", "integer",
              function ($attribute, $value, $fail) {
                if (User::whereId($value)->count() ==0) {
                    $fail(trans("messages.userNotFound"));
                }
              },
            ],
          ]);
        return $validator;
    }

    public function rulesaddWishList($data){
        $validator = Validator::make($data, [
            "treatment_id" => ["required", "integer",
            function ($attribute, $value, $fail) {
              if (Treatment::whereId($value)->count() ==0) {
                  $fail(trans("messages.treatmentNotFound"));
              }
            },
          ],
          ]);
        return $validator;
    }
    public function rulesuserRequestRating($data){
        $validator = Validator::make($data->all(), [
            "request_id" => ["required", "integer",
            function ($attribute, $value, $fail) use($data) {
              if (UserRequest::where([["id",$value],["user_id",$data->user()->id]])->count() ==0) {
                  $fail(trans("messages.invalidRequest"));
              }
            },
          ],
          "rating"=>"required|in:1,2,3,4,5",
          "feedback" =>"required",
          ]);

          return $validator;
    }
    public function rulesFavouriteRequest($data){
        $validator = Validator::make($data,[
                        "request_id" => ["required", "integer",function ($attribute, $value, $fail) {
                         $userRequestData = UserRequest::whereId($value);
                    if ($userRequestData->count() ==0) {
                            $fail(trans("messages.requestNotFound"));
                    }else{
                            $data = $userRequestData->first();
                            $count = UserTreatment::where(["area_id"=>$data->area_id,"category_id"=>$data->category_id,"sub_category_id"=>$data->sub_category_id,"treatment_id"=>$data->treatment_id])->count();
                        if($count ==0){
                            $otherCount = UserTreatment::where(["area_id"=>$data->area_id,"category_id"=>$data->category_id,"sub_category_id"=>$data->sub_category_id])->count();
                            if($otherCount ==0)
                            $fail(trans("messages.InvalidRequest"));
                        }
                    }
                },
            ],
        ]);
        return $validator;
        }
    public function getUsersSearch($data, $role, $appendParameters){
        $flag = $appendParameters['search_type'] == $role ? true : false;

        $orderBy = !empty($appendParameters[$role.'_order_by']) ? explode('_', $appendParameters[$role.'_order_by']) : ['id', 'desc'];
        $searchQuery = trim($appendParameters['search_keyword']);
        $searchIn = ['id', 'name', 'email', 'phone','is_active'];
        $searchData = ['data'=>$data, 'flag'=>$flag, 'searchQuery'=>$searchQuery, 'searchIn'=>$searchIn];


        $users = User::role($role)
        ->where(function ($q) use ($searchData) {
                $q->when($searchData['flag'], function ($q) use ($searchData){

                    foreach ($searchData['searchIn'] as $field){
                        $q->orWhere($field, 'like', "%{$searchData['searchQuery']}%");

                    }
                });
            })->orderBy($orderBy[0], $orderBy[1])->paginate(15, ['*'], $role)->appends($appendParameters);

        return $users;
    }
    /**
     * The accessors to append to the model's array form.
     *
     * @var array
    */
    protected $appends = ['file_url'];

    /**
     * Get File URL.
     *
     * @return bool
     */
    public function getFileUrlAttribute()
    {
        if (isset($this->attributes['profile_photo_path'])) {
          return $this->attributes['file_url'] = asset('storage/'.str_replace('public/', '' ,$this->attributes['profile_photo_path']));
        }
    }

    public function userWorkExperience(){
        return $this->hasMany("\App\Models\UserExperience");
    }
    public function userRegistration(){
        return $this->hasMany("\App\Models\UserRegistration");
    }
    public function userEducation(){
        return $this->hasMany("\App\Models\UserEducation");
    }
    public function userAddresses(){
        return $this->hasMany("\App\Models\UserAddress");
    }
    public function userDetails(){
      return $this->hasOne("\App\Models\UserDetail");
    }
    public function doctorPortfolio(){
        return $this->hasMany("\App\Models\DoctorPortfolio");
    }
    public function doctorHospitalClinic(){
        return $this->hasMany("\App\Models\DoctorHospitalClinic");
    }
    public function userBusinessInfo(){
        return $this->hasOne("\App\Models\UserBusinessInformation");
    }
    public function userPaymentInformation(){
        return $this->hasOne("\App\Models\UserPaymentInformation");
    }
    public function supervisor(){
        return $this->hasOne("\App\Models\Supervisor");
    }
    public function getArea(){

        return $this->belongsToMany(Area::class,'user_treatments','user_id','area_id');
    }
    public function getCategory(){

        return $this->belongsToMany(Category::class,'user_treatments','user_id','category_id');
    }
    public function getSubCategory(){

        return $this->belongsToMany(SubCategory::class,'user_treatments','user_id','sub_category_id');
    }
    public function getTreatment(){

        return $this->belongsToMany(Treatment::class,'user_treatments','user_id','treatment_id');
    }
    public function userTreatment(){
        return $this->hasMany("\App\Models\UserTreatment");

    }

}
