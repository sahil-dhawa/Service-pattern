<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Services\UserService;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;
use App\Models\Magazine;
use App\Models\UserAddress;
use App\Models\UserRegistration;
use App\Models\UserEducation;
use App\Models\UserExperience;
use Exception;



class UsersController extends Controller
{
    protected $service;
    public function __construct()
    {
        $this->service = new UserService(new User);
    }
    /**
    * @OA\Post(
    *    path="/register",tags={"User"},summary="User Registration",operationId="UserRegister",description= "Returns the success message with otp to email for verification. Returns the error message if validation error or any other error occurred.",

    *    @OA\Parameter(name="user_type",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Parameter(name="email",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Parameter(name="name",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Parameter(name="password",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Parameter(name="password_confirmation",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Response(response=200,description="OTP sent successfully to your email please verify to continue",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=401,description="Failed to send OTP. Please try again!!"),
    *    @OA\Response(response=400,description="Bad request"),
    * )
     **/
    public function register(Request $request){
        // return response()->send('this is message','200',[1,2,3,4]);
        $response = $this->service->register($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
    * @OA\Post(
    *    path="/login",tags={"User"},summary="User Login",operationId="UserLogin",description= "Returns the success message with token and user details. Returns the error message if validation error or any other error occurred.",
    *    @OA\Parameter(name="email",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Parameter(name="password",in="query",required=true,
    *    @OA\Schema(type="string")),
    *    @OA\Response(response=200,description="User logged in successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=401,description="Invalid Email/Password,Please verify your email to continue."),
    *    @OA\Response(response=400,description="Bad request"),
    * )
     **/
    public function login(Request $request){
        $response = $this->service->login($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
     * @OA\Post(
     * path="/validate-otp",tags={"User"},summary="Validate otp and login",operationId="validateOtp",description= "Validate otp and login.",security={{"bearerAuth":{}}},
     * @OA\Parameter(name="email",in="query",required=true,
     * @OA\Schema(type="string")),
     * @OA\Parameter(name="otp",in="query",required=true,
     * @OA\Schema(type="integer")),
     * @OA\Response(response=200,description="User logged in successfully",
     * @OA\MediaType(mediaType="application/json")),
     *  @OA\Response(response=400,description="Invalid Otp,Otp expired please regenerate new one,Invalid Username/Password"),
     * )
     */
    public function validateOtp(Request $request){
       $response = $this->service->validateOtp($request->all());
       return response()->send($response['message'],$response['status'],$response['data']);
    }
    public function validateToken(){
        $response = $this->service->validateToken();
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
    * @OA\Post(
    *    path="/re-send-otp",tags={"User"},summary="Resend OTP",operationId="reSendOtp",description= "Returns the success message and Details of the user. Returns the error message if validation error or any other error occurred.",
    *
    *    @OA\Parameter(name="email",in="query",required=true,
    *    @OA\Schema(type="string")),
    *
    *    @OA\Response(response=200,description="User logged in Successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *
    *    @OA\Response(response=203,description="Please verify account first"),
    *    @OA\Response(response=401,description="Invalid Login details,Please try again "),
    *    @OA\Response(response=400,description="Bad request"),
    * )
     **/
    public function reSendOtp(Request $request)
    {
      $response = $this->service->reSendOtp($request->all());

      $data = [];
      if($response['status'] != Response::HTTP_BAD_REQUEST){
          $data = $response['data'];
      }

      return response()->send($response['message'],$response['status'],$data);
    }

    /**
     * @OA\Get(
     * path="/manage-profile",tags={"User"},summary="manage profile",operationId="manageProfile",description= "manage profile of customer.",security={{"bearerAuth":{}}},
     * @OA\Response(response=200,description="User logged in successfully",
     * @OA\MediaType(mediaType="application/json")),
     * @OA\Response(response=203,description="Please verify account first"),
     * @OA\Response(response=401,description="Invalid Login details,Please try again "),
     * @OA\Response(response=400,description="Bad request"),
     * )
     **/
    public function manageProfile(Request $request)
    {
      $response = $this->service->userProfile($request,true);
      return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
      *  @OA\Post(path="/profile-update",tags={"User"},description="profile update.",operationId="profileUpdate", summary="Update image api",security={{"bearerAuth":{}}},
      *    @OA\RequestBody(required=true,@OA\MediaType(mediaType="multipart/form-data",
      *        @OA\Schema(
      *           @OA\Property(description="Profile pic to upload",property="files",type="file",format="formData"),
      *           @OA\Property(property="user_id", type="integer"),
      *           @OA\Property(property="type", type="string", example="profile_pic"),
      *           @OA\Property(property="phone", type="integer", example="1234567890"),
      *           @OA\Property(property="dob", type="string", format="date", example="2000-05-23"),
      *           @OA\Property(property="marital_status", type="string",description= "0=>married,1=>unmarried"),
      *        )
      *     )
      *  ),
      *  @OA\Response(response=200,description="Success",
      *     @OA\MediaType(mediaType="application/json")),
      *  )
    */

    public function profileUpdate(Request $request)
    {
      $response = $this->service->profileUpdate($request);
      return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
     * @OA\Post(
     * path="/forgot-password",tags={"User"},summary="Validate email and send reset password link.",operationId="forgotPassword",description= "Validate email and send reset password link.",
     * @OA\Parameter(name="username",in="query",required=true,
     *       @OA\Schema(type="string")),
     * @OA\Response(response=200,description="We have emailed your password reset link!",
     * @OA\MediaType(mediaType="application/json")),
     *  @OA\Response(response=400,description="Invalid username"),
     * )
     */
    public function forgotPassword(Request $request){
        $response = $this->service->forgotPassword($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }

        /**
     * @OA\post(
     * path="/change-password",tags={"User"},summary="change password",operationId="changePassword",description= "change password.",security={{"bearerAuth":{}}},
     *
     * @OA\Parameter(name="current_password",in="query",required=true,
     * @OA\Schema(type="string")),
     *
     * @OA\Parameter(name="new_password",in="query",required=true,
     * @OA\Schema(type="string")),
     *
     * @OA\Parameter(name="confirm_password",in="query",required=true,
     * @OA\Schema(type="string")),
     *
     * @OA\Response(response=200,description="User logged in successfully",
     * @OA\MediaType(mediaType="application/json")),
     *
     * @OA\Response(response=203,description="Please verify account first"),
     * @OA\Response(response=401,description="Invalid Login details,Please try again "),
     * @OA\Response(response=400,description="Bad request"),
     * )
     */
    public function changePassword(Request $request)
    {
      $response = $this->service->changePassword($request);
      return response()->send($response['message'],$response['status'],$response['data']);
    }
    public function permanentDelete(Request $request){
        $response = $this->service->permanentDelete($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
    * @OA\Delete(
    *    path="/remove-user",tags={"Admin"},summary="Delete User",operationId="removeUser",description= "Returns the success when User Deleted. Returns the error message when any error occurred.",security={{"bearerAuth":{}}},
    *    @OA\Parameter(name="user_id",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Response(response=200,description="Account removed successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=400,description="Bad request"),
    * )
    **/
    public function removeUser(Request $request){
        $response = $this->service->permanentDelete($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
      *  @OA\Post(path="/change-profile-picture",tags={"User"},description="update profile picture.",operationId="updatePicture", summary="Update image api",security={{"bearerAuth":{}}},
      *    @OA\RequestBody(required=true,@OA\MediaType(mediaType="multipart/form-data",
      *        @OA\Schema(
      *           @OA\Property(description="Profile pic to upload",property="image",type="file",format="formData"),
      *        )
      *     )
      *  ),
      *  @OA\Response(response=200,description="Profile picture updated successfully",
      *     @OA\MediaType(mediaType="application/json")),
      *  )
    */
    public function updateProfilePicture(Request $request){
        $response = $this->service->uploadPicture($request);
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
    *    @OA\Post(
    *        path="/logout",summary="Logout",operationId="logout",description= "Logout .",security={{"bearerAuth":{}}},
    *
    *       @OA\Response(response=200,description="Logout successfully",
    *        @OA\MediaType(mediaType="application/json")),
    *
    *    )
     */
    public function logout(){

        $response = $this->service->userLogout();
        return response()->send($response['message'],$response['status'],$response['data']);
    }

        /**
    * @OA\get(
    *    path="/get-users",tags={"Admin"},summary="Get All Users",operationId="getUsers",description= "Returns the success message and all users with their rols. Returns the error message if User has not Access or any other error occurred.",security={{"bearerAuth":{}}},

    *    @OA\Parameter(name="search_type",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Parameter(name="search_keyword",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Parameter(name="order_by",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Response(response=200,description="get all user Successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=400,description="Bad request"),
    * )
     **/

    public function getUsers(Request $request) {
      $response = $this->service->getUsers($request->all());
      return response()->send($response['message'],$response['status'],$response['data']);
    }
    /**
    * @OA\Delete(
    *    path="/activate-inactivate-user",tags={"Admin"},summary="Activate/Inactivate User",operationId="deleteUser",description= "Returns the success when User Activated or Deactivated. Returns the error message when any error occurred.",security={{"bearerAuth":{}}},
    *    @OA\Parameter(name="user_id",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Response(response=200,description="user Deleted Successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=400,description="Bad request"),
    * )
    **/

    public function deleteUser(Request $request){
      $response = $this->service->deleteUser($request->all());
      return response()->send($response['message'],$response['status'],$response['data']);
    }

    /**
    * @OA\Post(
    *    path="/activate-deactivate-account",summary="Activate/Deactivate  User Account",operationId="deactivateActivateUser",description= "Returns the success when User Deactivated or Activated. Returns the error message when any error occurred.",security={{"bearerAuth":{}}},
    *    @OA\Parameter(name="user_id",in="query",
    *    @OA\Schema(type="string")),
    *
    *    @OA\Response(response=200,description="user Deleted Successfully",
    *    @OA\MediaType(mediaType="application/json")),
    *    @OA\Response(response=400,description="Bad request"),
    * )
    **/
    public function deactivateAccount(Request $request){
        $data = $request->user()->toArray();
        $data['user_id'] = $data['id'];

        $response = $this->service->deleteUser($data);
        return response()->send($response['message'],$response['status'],$response['data']);
    }
    public function contactUs(Request $request){
        $response = $this->service->contactUs($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);

      }
    /**
     * @OA\GET(
     * path="/landingPage",tags={"User"},summary="Return details corresponding to treatments and influencers",operationId="landingPage",description= "landingPage Details.",security={{"bearerAuth":{}}},
     * @OA\Response(response=200,description="landingPage details!",
     * @OA\MediaType(mediaType="application/json")),
     *  @OA\Response(response=400,description="Invalid username"),
     * )
     */
    public function landingPage(Request $request){
        $response = $this->service->landingPage($request->all());
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    // get users details
    public function profileDetails(Request $request,$id=null){
        $response = $this->service->userDetails($request,$id);
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    public function users(Request $request){
        $response = $this->service->users($request);
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    public function usersListing(Request $request){
      $response = $this->service->usersListing($request);
      return response()->send($response['message'],$response['status'],$response['data']);
    }
      /**
  * @OA\Get(
  *    path="/get-magazines",tags={"User"},summary="Magazine Details",operationId="magazineDetails",description= "Magazine Details.",security={{"bearerAuth":{}}},
  *    @OA\Parameter(name="magazine_id",in="query",
  *    @OA\Schema(type="integer")),
  *    @OA\Parameter(name="limit",in="query",
  *    @OA\Schema(type="integer")),
  *
  *    @OA\Response(response=200,description="Magazine Details",
  *    @OA\MediaType(mediaType="application/json")),
  *    @OA\Response(response=400,description="Bad request"),
  * )
   **/
    public function magazines(Request $request , Magazine $magazine_id=null){
        $response = $this->service->getMagazines($request,$magazine_id);
        return response()->send($response['message'],$response['status'],$response['data']);
    }
        /**
     * @OA\Post(
     * path="/add-treatments-to-whishlist",tags={"User"},summary="Add Treatments To Whishlist",operationId="whishlist",description= "Add Treatments To Whishlist",security={{"bearerAuth":{}}},
     * @OA\Parameter(name="treatment_id",in="query",required=true,
     * @OA\Schema(type="integer")),
    * @OA\Response(response=200,description="Wishlist added successfully",
     * @OA\MediaType(mediaType="application/json")),
     *  @OA\Response(response=400,description="Treatment not found"),
     * )
     */
    public function addWishList(Request $request){
      $response = $this->service->addWishList($request);
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    public function userRequestRating(Request $request){
        $response = $this->service->userRequestRating($request);
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    public function getYourselfVerified(Request $request){
        $response = $this->service->getYourselfVerified($request);
        return response()->send($response['message'],$response['status'],$response['data']);
    }

    public function removeAddressEducationWork(Request $request,$id,$type){

        switch ($type) {
            case 'registration':
                $model = UserRegistration::class;
                $message = trans("messages.registrationRemoved");
                break;
            case 'education':
                $model = UserEducation::class;
                $message = trans("messages.educationRemoved");
                break;
            case 'experience':
                $model = UserExperience::class;
                $message = trans("messages.experienceRemoved");
                break;
            default:
                $model = UserAddress::class;
                $message = trans("messages.addressRemoved");
            break;
        }
        try{
            $model::FindorFail($id)->delete();
            $status = Response::HTTP_OK;
        }catch(Exception $e){
            $message = $e->getMessage();
            $status = Response::HTTP_BAD_REQUEST;
        }
        return response()->send($message,$status);
    }
}


