package rw.auth.v1.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import rw.auth.v1.dtos.*;
import rw.auth.v1.enums.EUserStatus;
import rw.auth.v1.exceptions.AppException;
import rw.auth.v1.models.User;
import rw.auth.v1.payload.ApiResponse;
import rw.auth.v1.payload.JWTAuthenticationResponse;
import rw.auth.v1.security.JwtTokenProvider;
import rw.auth.v1.services.IUserService;
import rw.auth.v1.services.MailService;
import rw.auth.v1.utils.Mapper;
import rw.auth.v1.utils.Profile;
import rw.auth.v1.utils.Utility;

import javax.validation.Valid;

@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthenticationController {

    private final IUserService userService;
    private final MailService mailService;
    private final JwtTokenProvider jwtTokenProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationController(IUserService userService, MailService mailService, JwtTokenProvider jwtTokenProvider, BCryptPasswordEncoder bCryptPasswordEncoder, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.mailService = mailService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(path = "/login")
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody SignInDTO signInDTO){
        String jwt = null;
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInDTO.getEmail(),signInDTO.getPassword()));
        try{
            SecurityContextHolder.getContext().setAuthentication(authentication);
            jwt = jwtTokenProvider.generateToken(authentication);
        }
        catch (Exception e){
        }

        return ResponseEntity.ok(ApiResponse.success(new JWTAuthenticationResponse(jwt)));
    }

    @PutMapping(path = "/verify-email")
    public ResponseEntity<ApiResponse> verifyEmail(@Valid @RequestBody VerifyUserEmailDTO dto){
        userService.verifyEmail(dto.getEmail(), dto.getActivationCode());
        return ResponseEntity.ok(ApiResponse.success("Email Verification successfully completed"));
    }

    @PostMapping(path ="/initiate-password-reset")
    public ResponseEntity<ApiResponse> initiatePasswordReset(@Valid @RequestBody InitiatePasswordResetDto dto){
        User user = this.userService.getByEmail(dto.getEmail());
        user.setActivationCode(Utility.randomUUID(6,0,'N'));
        this.userService.save(user);

        mailService.sendResetPasswordMail(user);

        return ResponseEntity.ok(new ApiResponse(true,"Password Reset Email Sent successfully"));
    }

    @PostMapping(path="/check-code")
    public ResponseEntity<ApiResponse> checkActivationCode(@Valid @RequestBody CheckActivationCodeDto dto){
        return ResponseEntity.ok(ApiResponse.success(userService.isCodeValid(dto.getEmail(), dto.getActivationCode())));
    }

    @PostMapping(path="/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(@RequestBody @Valid ResetPasswordDto dto){
        User user = this.userService.getByEmail(dto.getEmail());

        if(Utility.isCodeValid(user.getActivationCode(),dto.getActivationCode())){
            user.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
            user.setActivationCode(Utility.randomUUID(6,0,'N'));
            user.setStatus(EUserStatus.ACTIVE);
            this.userService.save(user);
        }
        else{
            throw new AppException("Invalid code");
        }
        return ResponseEntity.ok(new ApiResponse(true,"Password successfully reset"));
    }

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse> getProfile(){
        Profile profile = userService.getLoggedInProfile();
        return ResponseEntity.ok(ApiResponse.success(profile));
    }

    @PutMapping("/update-profile")
    public ResponseEntity<ApiResponse> updateProfile(@Valid @RequestBody UpdateUserDTO dto){
        User user = Mapper.getUserFromDTO(dto);
        User actualUser =userService.getLoggedInUser();
        userService.update(actualUser.getId(),user);

        return ResponseEntity.ok(ApiResponse.success("Successfully updated profile"));
    }

    @PutMapping("/change-password")
    public ResponseEntity<ApiResponse> changePassword(@Valid @RequestBody ChangePasswordDTO dto){
        User user =userService.getLoggedInUser();
        if(!bCryptPasswordEncoder.matches(dto.getCurrentPassword(),user.getPassword())){
            return ResponseEntity.badRequest().body(ApiResponse.fail("Invalid current password"));
        }
        user.setPassword(bCryptPasswordEncoder.encode(dto.getNewPassword()));
        userService.save(user);

        return ResponseEntity.ok(ApiResponse.success("Successfully changed the password"));
    }
}
