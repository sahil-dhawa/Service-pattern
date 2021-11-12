<?php
namespace App\Services;
use App\Models\User;
use App\Models\Wishlist;
use App\Models\Influencer;
use Illuminate\Support\Facades\Validator;

use Illuminate\Support\Facades\Hash;
use App\Mail\SendOtp;
use App\Models\UserOtp;
use App\Models\Treatment;
use App\Models\SubCategory;
use App\Models\Area;
use App\Models\Category;
use App\Models\TreatmentRelation;
use Symfony\Component\HttpFoundation\Response;
use DB;
use Auth;
use Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Password;
use Spatie\Permission\Models\Role;
use Exception;
use App\Models\Magazine;
use App\Models\Questionaire;
use App\Mail\ContactUs;
use GuzzleHttp\Psr7\Request;
use App\Models\Article;
use App\Models\UserRating;
use App\Mail\VerifyDoctor;
use App\Notifications\VerifyDoctor as VerifyDoctorNotification;

class UserService{

    protected $success,$failure,$obj;
    public function __construct($obj)
    {
        $this->obj = $obj;
        $this->success = Response::HTTP_OK;
        $this->failure = Response::HTTP_BAD_REQUEST;
    }

    public function register($data){

        $response = $this->obj->rulesRegister($data); // Validations in user model
        if ($response->fails()) {
            return prepareApiResponse($response->errors()->first(), $this->failure); //error
        }
        // Initially setting status of doctor to inactive
        $is_active = ($data['user_type'] =='Doctor') ? config("constants.inactive") : config("constants.active");
        $code = generateUniqueCode();
        $user = User::updateOrCreate(["email"=>$data['email']],
            ["email"=>$data['email'],"name"=>$data['name'],"password"=>Hash::make($data['password']),"is_active"=>$is_active,"unique_code"=>$code]
        );
        if($data['user_type'] =='Doctor'){
            $user->assignRole('Doctor'); // assign role
        }else if($data['user_type'] =='Patient'){
            $user->assignRole('Patient'); // assign role
        }else if($data['user_type'] =='Clinic'){
            $user->assignRole('Clinic'); // assign role
        }


        $user->otp = $this->generateOtp($user);  //Generating otp for new user

        $status = $this->success;
        // send OTP
        $data = [
            'email' => $user->email,
            'otp' => $user->otp
        ];
        $status = $this->sendOTP($data, $status); // send OTP and returns status
        $message = trans("messages.otpSuccess");
        if ($status != $this->success) {
            $message = trans("messages.failedToSendOtp");
        }
        return prepareApiResponse($message, $status, $user);
    }
    public function login($data){
        $response = $this->obj->rulesLogin($data); // Validations in user model
        if ($response->fails()) {
            return prepareApiResponse($response->errors()->first(), $this->failure); //error
        }
        $message = trans("messages.invalidCredentials");
        $status = $this->failure;

        $user = User::whereEmail($data['email'])->withTrashed()->first();
        if(Auth::attempt(["email"=>$data['email'],"password"=>$data['password']])){
            if(Auth::user()->hasRole('Super-Admin')){
                $message = trans("messages.invalidCredentials");
                Auth::logout();
                return prepareApiResponse($message, $this->failure); //error
            }elseif(!Auth::user()->email_verified_at ){
                $message = trans("messages.emailNotVerified");
                Auth::logout();
            }else{
                $user = Auth::user();
                $user->last_login = date("Y-m-d H:i:s");
                $user->save();
                $status = $this->success;
                $user->token = Auth::User()->createToken('token')->accessToken;
                $user->roles = Auth::User()->roles;
                $message = trans("messages.userLoginSuccess");
            }
        }else{
            $user = array();
        }

        return prepareApiResponse($message, $status, $user);
    }

    public function generateOtp($user){
        $userOtp = UserOtp::updateOrCreate(
          ["user_id"=>$user->id],
          ["otp"=>$this->generateBarcodeNumber()],
        );

        return $userOtp->otp;
    }

    public function reSendOtp($data)
    {
      $username = trim(strtolower($data['email']));
      $query = (is_numeric($username)) ?  User::wherePhone($username) : User::whereEmail($username);
      $user = $query->first();
      $user->otp = $this->generateOtp($user);
      $status = Response::HTTP_OK;
      $message = trans("messages.validateUsername");

      $data = [
          'email' => $username,
          'otp' => $user->otp
      ];
      $status = $this->sendOTP($data, $status); // send OTP and returns status
      if ($status != Response::HTTP_OK) {
        $status = Response::HTTP_BAD_REQUEST;
        $message = trans("messages.failedToSendOtp");
      }

      return prepareApiResponse($message, $status, $user);
    }
    public function getYourselfVerified($data){
       $user =  User::role("Super-Admin")->first();

       if($data->user()->is_active ==2){
        $user->notify(new VerifyDoctorNotification($data->user()));

        $message = trans("messages.verificationMailSent");
        $status = $this->success;


       }elseif($data->user()->is_active ==1){
            $message = trans("messages.userAlreadyVerified");
            $status = $this->failure;

       }
       return prepareApiResponse($message,$status);
    }
    public function sendOTP($data = [], $status) // send OTP and returns status
    {
      Mail::to($data['email'])->send(new SendOtp($data));
      if (Mail::failures()) { // check for failures
          $status = 4; // return response showing failed emails
      }
      return $status;
    }

    function generateBarcodeNumber() {
        $number = mt_rand(10000, 99999); // better than rand()

        // call the same function if the barcode exists already
        if ($this->numberExists($number)) {
            return $this->generateBarcodeNumber();
        }

        // otherwise, it's valid and can be used
        return $number;
    }
    function numberExists($number) {
        // query the database and return a boolean
        // for instance, it might look like this in Laravel
        return UserOtp::whereOtp($number)->exists();
    }
    public function validateOtp($data){
        $validator = Validator::make($data,[
            "email"=>"required|email",
            "otp"=>["required","integer",function($attribute,$value,$fail)use($data){
                $resp = $this->checkOtp($value,null,110);//3rd parameter denotes time of expiry
                switch($resp){
                    case 0:
                        $fail(trans("messages.invalidOtp"));
                    break;
                    case 2:
                        $fail(trans("messages.otpExpired"));
                    break;
                }

              }],
        ]);
        if($validator->fails()){
            return prepareApiResponse($validator->errors()->first(),Response::HTTP_BAD_REQUEST);
        }

     
        $user = User::whereEmail($data['email'])->first();

       

            UserOtp::where([["otp",$data['otp']],["user_id",$user->id]])->delete();
            $user->email_verified_at = date("Y-m-d H:i:s");
            $user = DB::transaction(function()use($user){
                $user->save();
                $user->token = $user->createToken('token')->accessToken;
                return $user;
            });


            return prepareApiResponse(trans("messages.userLoginSuccess"),$this->success,$user);
        
    }
    public function userLogout(){
        if(Auth::check()){
            Auth::user()->token()->revoke();
            return prepareApiResponse(trans("auth.logoutSuccess"),$this->success);
        }
        return prepareApiResponse(trans("auth.logoutFailure"),$this->failure);
    }
    public function forgotPassword($data){
       $response = $this->obj->rulesForgotPassword($data);
       if($response->fails()){
        return prepareApiResponse($response->errors()->first(),$this->failure);
       }
       $resp = Password::sendResetLink(["email"=>$data['username']]);
       $status = $resp == "passwords.sent" ?$this->success : $this->failure;
       return prepareApiResponse(trans($resp),$status);
    }
    public function uploadPicture($request){

        $data = $request->all();

        $response = $this->obj->rulesUploadPicture($data);
        if($response->fails()){
            return prepareApiResponse($response->errors()->first(),Response::HTTP_BAD_REQUEST);
        }
        if($request->user()->profile_photo_path){
            Storage::delete($request->user()->profile_photo_path);
        }
        $request->user()->profile_photo_path = uploadFiles($request,"image");
        $request->user()->save();
        return prepareApiResponse(trans("messages.profilePicUpdated"),$this->success,$request->user());
    }
    public function profileUpdate($data)
    {

      $validator = Valiadator::make($data->all(),[
        "user_id"=>"required",
        "type"=>"required",
        "phone"=>["nullable","integer","digits:10",function ($attribute, $value, $fail) {
            $phone_exists = User::wherePhone($value)->first();
            if(!is_null($phone_exists)){
                $fail('The '.$attribute.' '.$value.' already used');
            }
        },],
      ]);
      if($validator->fails()){
        return prepareApiResponse($validator->errors()->first(),Response::HTTP_BAD_REQUEST);
      }
      $user = User::find($data->user_id);
      if($data->hasFile('files')){
        $file_path = $this->uploadFiles($data);
        if ($file_path['status'] == 3) {
          return prepareApiResponse($file_path['message'], Response::HTTP_BAD_REQUEST);
        }
        if (!is_null($user->profile_photo_path)) {
          Storage::delete($user->profile_photo_path);
        }
        $user->profile_photo_path = $file_path['path'];
      }

      $user->name = $data->name ?? null;
      $user->phone = $data->phone ?? null;
      $user->dob = $data->dob ?? null;
      $user->marital_status = $data->marital_status ?? null;
      $user->save();

      return prepareApiResponse(trans("messages.ProfileUpdatedSuccess"), Response::HTTP_OK, $user);
    }

    public function addUser($data)
    {
     
      $user = new User;
      if($data->hasFile('profile_pic')){
        $file_path = uploadFiles($data['profile_pic'],'document','public/doctor/business_infooo',1);;
        $user->profile_photo_path = $file_path;
      }

      $user->name = $data->name ?? null;
      $user->email = $data->email ?? null;
      $user->password = bcrypt($data->password);
      // Hash::make($data['password'])
      if($data['user_type'] =='Doctor'){
        $user->assignRole('Doctor'); // assign role
      }else if($data['user_type'] =='Patient'){
          $user->assignRole('Patient'); // assign role
      }

      $user->save();

      return prepareApiResponse(trans("messages.ProfileUpdatedSuccess"), Response::HTTP_OK, $user);
    }

    public function getareas(){
        $data = getAreas();
        return prepareApiResponse(trans("messages.areaList"), Response::HTTP_OK, $data);
    }

    public function uploadFiles($data)
    {
      $flag = false; $paths = [];
      if($data->hasFile('files')){
        if ($data->type != 'profile_pic') { // if 'type' field is incorrect i.e. it must have predefined type like "profile_pic" and some other type
          return array("status"=>3, "message" => 'incorrect type field');
        }
        ///////////////// For single file ////////////////////
        if ($data->type == 'profile_pic') {
          $file = $data->file('files');
          $name = $file->getClientOriginalName();
          $path_parts = pathinfo($name);
          $fileExtension = $path_parts['extension'];
          if (!in_array($fileExtension, ['jpg','png','jpeg','jpg'])) {
            return array("status"=>3, "message" => trans("messages.wrongFileExtention"));
          }

          $path = Storage::putFile('public/photos', $data->file('files'));
          return array("status"=> 1, "path"=>$path);
        }


      }

      return array("status"=> 1, "files_path"=>$paths);
    }

    public function userProfile($request,$includeRoles=false){

        $user = fetchProfile($request->user(),$includeRoles);

        $message = trans("messages.success");
        $status = $this->success;
        return prepareApiResponse($message,$status,$user);
    }

    public function changePassword($request)
    {
        $user = $request->user();
        $validator = Validator::make($request->all(),[
        "current_password"=>["required",function($attribute,$value,$fail) use($user){
            if (!(Hash::check($value, $user->password))) {
                $fail(trans("messages.invalidCurrentPassword"));
            }
        }],
        "new_password"=>"required|min:6",
        "confirm_password"=>"required | min:6 | same:new_password",
      ]);
      if($validator->fails()){
        return prepareApiResponse($validator->errors()->first(), Response::HTTP_BAD_REQUEST);
      }

      if(!$request->otp){
        $user->otp = $this->generateOtp($request->user());
        $data = [
            'email' => $user->email,
            'otp' => $user->otp
        ];
        $status = Response::HTTP_OK;
        $status = $this->sendOTP($data, $status); // send OTP and returns status
        if ($status != Response::HTTP_OK) {
            $status = Response::HTTP_BAD_REQUEST;
            $message = trans("messages.failedToSendOtp");
        }
        return prepareApiResponse(trans("messages.otpSuccess"),$this->success,$user);
      }

      $resp = $this->checkOtp($request->otp,$user->id);//3rd parameter denotes time of expiry

      switch($resp){
            case "0":
               return prepareApiResponse(trans("messages.invalidOtp"),$this->failure);
            break;
            case "2":
                $user->otp = $this->generateOtp($request->user());
                return prepareApiResponse(trans("messages.otpExpiredNewGenerated"),$this->failure,$user);
            break;
        }
      if (!(Hash::check($request->current_password, $user->password))) {
        return prepareApiResponse(trans("messages.invalidCurrentPassword"), Response::HTTP_BAD_REQUEST);
      }
      if (strcmp($request->current_password, $request->new_password) == 0) {
        return prepareApiResponse(trans("messages.newAndOldPasswordSame"), Response::HTTP_BAD_REQUEST);
      }

      $user->password = bcrypt($request->new_password);
      if ($user->save()) {
        return prepareApiResponse(trans("messages.passwordUpdated"), Response::HTTP_OK, $user);
      }
    }
    // Function for recovering and disabling user
    public function deleteUser($data,$bySuperAdmin=0) {

        $response = $this->obj->rulesdeleteUser($data); // Validations in user model
        if ($response->fails()) {
        return prepareApiResponse($response->errors()->first(), $this->failure); //error
        }
        $user = User::whereId($data['user_id'])->withTrashed()->first();

        $message = __("messages.userDelete");
        if (!$user->is_active) {
          $user->is_active =1;
          $user->save();
          $message = __("messages.userRestore");
        } else {
          $user->is_active = 0;
          $user->save();
        }
      return prepareApiResponse($message,$this->success,$user);
  }

    public function userDetails($request,$id=null){
      if($request->is("api/*")){
        $models = "userDetails";
        if(Auth::user()->hasRole('Clinic')) {
          $models = ['userDetails', 'userAddresses'];
        }

        $data =  User::with($models)->whereId($id)->get();
        return prepareApiResponse(trans("messages.userDetails"), $this->success, $data);
      }

      $data = User::find($id);
      return $data;
    }

    public function getUsers($data,$request=null) {
    try {

      $roles = Role::whereNotIn('name', ['Super-Admin'])->pluck('name')->toArray();
      $appendParameters = $this->userOrderby($roles, $data);
      foreach($roles as $role){
        $users[$role] = $this->obj->getUsersSearch($data, $role, $appendParameters); // search user with role and if search query
      }
      $users['appendParameters'] = $appendParameters;
      $message = trans('messages.getusersSuccess');
      return prepareApiResponse($message, $this->success, $users);
    } catch (Exception $e) {
      $message = $e->getMessage();
      return prepareApiResponse($message, $this->failure);
    }
  }

  function userOrderby($roles, $data){
    $orderByParameter = [];
    $searchParameters = ['search_type', 'search_keyword'];
    foreach($roles as $role){
      array_push($orderByParameter, $role.'_order_by');  // create Order by parametes when admin sort and pagination for multiple Roles
    }
    $appendParameterNames = array_merge($roles, $searchParameters, $orderByParameter);
    foreach($appendParameterNames as $name){
      $appendParameters[$name] = @$data[$name];  // assign variable to pagination link, they append in pagination links
      if(@$data['search_type'].'_order_by' == $name){
        $appendParameters[$name] = !empty($data['order_by']) ? $data['order_by'] : 'id_desc';
      }
    }
    return $appendParameters;
  }
  public function contactUs($data){
    $response = $this->obj->rulesContactUs($data);
    if ($response->fails()) {
        return prepareApiResponse($response->errors()->first(), $this->failure); //error
    }
    try{
        Mail::to(config("constants.personal_email"))->send(new ContactUs($data));
        return prepareApiResponse(trans("messages.contactSuccess"), $this->success);
    }catch(Exception $e){
        return prepareApiResponse($e->getMessage(), $this->failure);
    }
  }
  public function permanentDelete($data){

    if(Auth::user()->hasRole('Super-Admin')){
        $response = $this->obj->rulesPermanentDelete($data);
        if ($response->fails()) {
            return prepareApiResponse($response->errors()->first(), $this->failure); //error
        }
        User::whereId($data['user_id'])->forceDelete();
    }else{
       Auth::user()->forceDelete();
       Auth::user()->token()->revoke();

       return prepareApiResponse(trans("messages.accountRemoved"),$this->success);
    }
  }

  public function landingPage($data){
    $influencers = Influencer::all();

    $area_with_treatments = Treatment::with("treatments")->where("type",'1')->get();
    $data['influencers'] = $influencers;
    $data['area'] = $area_with_treatments;
    return prepareApiResponse(trans("messages.dashboard"),$this->success,$data);
  }
  public function users($request){
    $data = Treatment::where("type","4")->where()->paginate();
    return prepareApiResponse(trans("messages.dashboard"),$this->success,$data);
  }
/* Function for checking whether token is valid or not,
    return success on valid and failure if token is expired */
  public function validateToken(){
      if(Auth::guard('api')->check()){
        return prepareApiResponse(trans("messages.validToken"),$this->success);
      }
      return prepareApiResponse(trans("messages.invalidToken"),$this->failure);
  }
public function getAreaWithCategory($request){

  $area = Area::with(['category' => function($query) {
                  $query->distinct()->orderBy('id','DESC');
                  }])->orderBy('id', 'DESC')->get()
                  ->map(function($area) {
                  $area->setRelation('category', $area->category->take(3));
            return $area;
            });
       $areaWithCategory  =  $area->map(function ($item, $key) {

              return [
              'id'=>$item->id,
              'title'=>$item->title,
              'url' => asset('storage/'.str_replace('public/', '' ,$item->url)),
              'description'=>$item->description,
              'created_at'=>$item->created_at,
              'updated_at'=>$item->updated_at,
              'category'=>$item->category->map(function ($item, $key) {
                                  return[
                                  'id'=>$item->id,
                                  'title'=>$item->title,
                                  'url'=>asset('storage/'.str_replace('public/', '' ,$item->url)),
                                  'description'=>$item->description,
                                  'created_at'=> $item->created_at,
                                  'updated_at'=>$item->updated_at,
                                  ];
              })

              ];
            });

    if (empty($area)) {
    return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }
    return prepareApiResponse(trans("messages.areaWithCategory"),$this->success,$areaWithCategory);

}

  public function getCategoriesByArea($request,$id){

  $categoriesByArea = Area::with(['category' => function($query) {
                            $query->distinct()->orderBy('id','DESC');
                            }])->where('id',$id)->get()
                            ->map(function ($item, $key) {

                          return [
                          'id'=>$item->id,
                          'title'=>$item->title,
                          'url' => asset('storage/'.str_replace('public/', '' ,$item->url)),
                          'description'=>$item->description,
                          'created_at'=>$item->created_at,
                          'updated_at'=>$item->updated_at,
                          'category'=>$item->category->map(function ($item, $key) {
                                              return[
                                              'id'=>$item->id,
                                              'title'=>$item->title,
                                              'url'=>asset('storage/'.str_replace('public/', '' ,$item->url)),
                                              'description'=>$item->description,
                                              'created_at'=> $item->created_at,
                                              'updated_at'=>$item->updated_at,
                                              ];
                          })

                          ];
                        });

  if (empty($categoriesByArea)) {
    return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
  }
  return prepareApiResponse(trans("messages.getcategoriesbyarea"),$this->success,$categoriesByArea);
  }

  public function getSubcategoriesByCategory($request,$id){

  $subcategoriesByCategory = Category::with(['subcategory' => function($query) {
                            $query->distinct()->orderBy('id','DESC');
                            }])->where('id',$id)->get()
                            ->map(function ($item, $key) {

                              return [
                              'id'=>$item->id,
                              'title'=>$item->title,
                              'url' => asset('storage/'.str_replace('public/', '' ,$item->url)),
                              'description'=>$item->description,
                              'created_at'=>$item->created_at,
                              'updated_at'=>$item->updated_at,
                              'subcategory'=>$item->subcategory->map(function ($item, $key) {
                                                  return[
                                                  'id'=>$item->id,
                                                  'title'=>$item->title,
                                                  'url'=>asset('storage/'.str_replace('public/', '' ,$item->url)),
                                                  'description'=>$item->description,
                                                  'created_at'=> $item->created_at,
                                                  'updated_at'=>$item->updated_at,
                                                  ];
                              })

                              ];
                            });

    if ($subcategoriesByCategory->isEmpty()) {
    return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }
    return prepareApiResponse(trans("messages.getsubcategoriesbyarea"),$this->success,$subcategoriesByCategory);

  }

  public function getTreatmentsBySubcategory($request,$id){

    $treatmentsBySubcategory = SubCategory::with(['treatment' => function($query) {
                                $query->distinct()->orderBy('id','DESC');
                                }])->where('id',$id)->get()
                                ->map(function ($item, $key) {
                                return [
                                'id'=>$item->id,
                                'title'=>$item->title,
                                'url' => asset('storage/'.str_replace('public/', '' ,$item->url)),
                                'description'=>$item->description,
                                'created_at'=>$item->created_at,
                                'updated_at'=>$item->updated_at,
                                'treatment'=>$item->treatment

                                ];
                                });

    if ($treatmentsBySubcategory->isEmpty()) {
    return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }

  return prepareApiResponse(trans("messages.getTreatmentsBySubcategory"),$this->success,$treatmentsBySubcategory);
  }

  public function getAllCategoriesByArea($request){

    $categoriesByArea = Area::with(['category'=>function($q){
        $q->distinct();
    }])->select("id")->whereIn('id',$request->area)->get()->filter(function($value,$key){
        foreach($value['category'] as $key=>$val){
            $val->area_id = $value->id;
        }
        return $value['category'];
    });


    if (count($categoriesByArea) ==0) {
      return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }
    return prepareApiResponse(trans("messages.getcategoriesbyarea"),$this->success,$categoriesByArea);
}
public function getAllSubCategoriesByCategory($request){
    $area_id = $category_id = array();
    foreach($request->category as $key=>$value){

        array_push($area_id,$value['area_id']);
        array_push($category_id,$value['category_id']);
    }

    $subcategoriesByCategory = Category::with(['subcategory'=>function($q)use($area_id){
        $q->whereIn("area_id",$area_id)->distinct();
    }])->select("id")->whereIn('id',$category_id)->get()->filter(function($value,$key) use($area_id){
        foreach($value['subcategory'] as $key=>$val){
            // $val->area_id = $area_id;
            $val->category_id = $value->id;
        }
        return $value['subcategory'];
    });


    if (count($subcategoriesByCategory) == 0) {
      return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }
    return prepareApiResponse(trans("messages.getsubcategoriesbycategory"),$this->success,$subcategoriesByCategory);
}
public function getAllTreatmentsBySubCategory($request){

    $area_id = $category_id = $sub_category_id =  array();
    foreach($request->subcategory as $key=>$value){

        array_push($area_id,$value['area_id']);
        array_push($category_id,$value['category_id']);
        array_push($sub_category_id,$value['sub_category_id']);
    }

    $treatmentBysubcategory = SubCategory::with(['treatment'=>function($q)use($area_id,$category_id){
        $q->whereIn("area_id",$area_id)
        ->whereIn("category_id",$category_id)
        ->distinct();
    }])
    ->select("id")
    ->whereIn('id',$sub_category_id)->get()->filter(function($value,$key){
        return $value['treatment'];
    });


    if (count($treatmentBysubcategory) ==0) {
      return prepareApiResponse(trans("messages.noRecordFound"), Response::HTTP_BAD_REQUEST);
    }
    return prepareApiResponse(trans("messages.getTreatmentsBySubcategory"),$this->success,$treatmentBysubcategory);
}

  public function usersListing($request){
    $role = ucfirst($request->get('role'));
    $models = "userDetails";
    if ($role == 'Clinic') {
      $models = ['userDetails', 'userAddresses'];
    }
    $data =  User::where('is_active', '!=' ,0)->role($role)->with($models)->paginate();
    return prepareApiResponse(trans("messages.success"),$this->success,$data);
  }

  public function getMagazines($request,$magazine){
    $limit = (isset($request->limit) && ($request->limit>0)) ? $request->limit : 0;
    $message = trans("messages.magazineDetail");

    if($request->magazine_id){
        $data = Magazine::find($request->magazine_id);
    }else{
        $data = ($limit) ? Magazine::limit($limit)->get() : Magazine::paginate();
    }

    return prepareApiResponse($message,$this->success,$data);
  }
  private function checkOtp($otp,$user_id=null,$time=300){

    $userId_exists = ($user_id ===null)?false : true;
    $userOtp =  UserOtp::when($userId_exists,function($q) use($otp,$user_id){
                    $q->where([["otp",$otp],["user_id",$user_id]]);
                },function($q) use($otp){
                    $q->where("otp",$otp);
                })->first();

    if(!$userOtp){
        return 0;
    }else{
      $differenceInSeconds =  calculateDifferenceInSeconds($userOtp->updated_at,date('Y-m-d H:i:s'));
      if($differenceInSeconds >$time) return 2;

      return 1; //success
    }
  }


  public function addWishList($request){
    $response = $this->obj->rulesaddWishList($request->all());
    if ($response->fails()) {

        return prepareApiResponse($response->errors()->first(), $this->failure); //error
    }
  $userId = Auth::user()->id;

   $previousWhishlist = Wishlist::where([['treatment_id', $request->treatment_id],['user_id',$userId]]);

   if($previousWhishlist->count()> 0){
    $previousWhishlist->delete();
    return prepareApiResponse(trans("messages.removeWishlist"),$this->success);
  }else{
    $addWishlist = new Wishlist;
    $addWishlist->treatment_id = $request->treatment_id;
    $addWishlist->user_id = $userId;
    $addWishlist->save();
    return prepareApiResponse(trans("messages.addWishlist"),$this->success);


   }
  }
  public function userRequestRating($request){

    $response = $this->obj->rulesuserRequestRating($request);
    if ($response->fails()) {
        return prepareApiResponse($response->errors()->first(), $this->failure); //error
    }
    UserRating::updateOrCreate(
        ["user_request_id"=>$request->request_id,"patient_id"=>$request->user()->id],
        ["user_request_id"=>$request->request_id,"patient_id"=>$request->user()->id,"rating"=>$request->rating,"review"=>$request->feedback]);
        return prepareApiResponse(trans("messages.requestRatedByPatient"),$this->success);
  }

  public function advanceSearch($request)
  {
    $flag = (!empty($request->area_id) ||
              !empty($request->name) ||
              !empty($request->category_id) ||
              !empty($request->subcategory_id)
            ) ? true : false;


    $treatments = DB::table('treatment_relations')
                ->join("treatments as trt","trt.id","=","treatment_relations.treatment_id")
                ->join("sub_categories as subcat","subcat.id","=","treatment_relations.sub_category_id")
                ->join("categories as cat","cat.id","=","treatment_relations.category_id")
                ->join("areas as area","area.id","=","treatment_relations.area_id")
                ->join("treatment_details as trd","trd.treatment_id","=","trt.id")
                ->select("treatment_relations.id",
                        "trt.id as treatment_id","trt.title as treatment_title","trt.description as treatment_description",
                        "subcat.id as treatment_sub_category_id","subcat.title as sub_category_name",
                        "cat.id as treatment_category_id","cat.title as category_name",
                        "area.id as treatment_area_id","area.title as area_name",
                        DB::raw("COUNT(trd.id) as no_of_videos")
                 )
                ->where("trd.type",1)
                ->when($flag, function ($q) use ($request) {
                    if (!empty($request->name)) {
                      $q->where('trt.title', 'like', '%' .$request->name. '%' );
                    }
                    if (!empty($request->area_id)) {
                        $q->where("treatment_relations.area_id", $request->area_id);
                    }
                    if (!empty($request->category_id)) {
                        $q->where("treatment_relations.category_id", $request->category_id);
                    }
                    if (!empty($request->subcategory_id)) {
                        $q->where("treatment_relations.sub_category_id", $request->subcategory_id);
                    }
                })
                // ->orderBy($orderBy, $sort)
                ->groupBy("treatment_relations.id")
                ->paginate();

    return prepareApiResponse(trans("messages.success"),$this->success,$treatments);
  }

  public function getAllArticlesByTreatment($request,$id)
  {
    $allArticles = Treatment::with('articles')->where('id', $id)->first();
    if ($allArticles === null) {
     return prepareApiResponse(trans("messages.invalidRecord"),$this->failure,$allArticles);
    }

    return prepareApiResponse(trans("messages.success"),$this->success,$allArticles);
  }

  public function articleDetail($request,$id)
  {
    $article = Article::with('treatments.treatmentDetails')->where('id', $id)->first();
    if ($article === null) {
        return prepareApiResponse(trans("messages.invalidRecord"),$this->failure,$article);
    }

    return prepareApiResponse(trans("messages.success"),$this->success,$article);
  }

  // if request coming from treatment detail page then treatment_id will be single (at 0 index of array)
  // if request coming from article detail page then treatment_ids will be multiple (in array) as, a single ariticle is mapped to multiple treatments.
  public function getRelatedTreatments($request)
  {
    $treatment_ids = $request->treatment_id;
    $sub_categories = Treatment::with('subCategory')->whereIn('id',$treatment_ids)->get();
    if ($sub_categories->isEmpty()) {
      return prepareApiResponse(trans("messages.invalidRecord"),$this->failure,$sub_categories);
    }

    $sub_categories = array_column($sub_categories->toarray(),'sub_category');
    $sub_categories = array_merge(...$sub_categories); // flatten array
    $sub_categorie_ids = array_unique(array_column($sub_categories,'id'));

    $related_treatments = TreatmentRelation::with('treatments')
                        ->whereIn('sub_category_id',$sub_categorie_ids)
                        ->whereNotIn('treatment_id',$treatment_ids)
                        ->get();

    $related_treatments = array_column($related_treatments->toarray(),'treatments');
    $related_treatments = array_map("unserialize", array_unique(array_map("serialize", $related_treatments))); // remove duplicate values from a multi-dimensional array

    return prepareApiResponse(trans("messages.success"),$this->success,$related_treatments);
  }




  public function questionnaireByTreatment($request)
  {
    $id = $request->treatment_id;
    $column = 'treatment_id';
    if (!empty($request->sub_category_id) && empty($request->treatment_id)) {
      $id = $request->sub_category_id;
      $column = 'sub_category_id';
    }

    $questionList = Questionaire::with('questionAnswer')->where($column, $id)->get();
    if ($questionList->isEmpty()) {
      return prepareApiResponse(trans("messages.invalidRecord"),$this->failure,$questionList);
    }

    return prepareApiResponse(trans("messages.success"),$this->success,$questionList);
  }

}
