package rw.auth.v1.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rw.auth.v1.dtos.*;
import rw.auth.v1.enums.EGender;
import rw.auth.v1.enums.ERole;
import rw.auth.v1.enums.EUserStatus;
import rw.auth.v1.exceptions.BadRequestException;
import rw.auth.v1.fileHandling.File;
import rw.auth.v1.fileHandling.FileStorageService;
import rw.auth.v1.models.Role;
import rw.auth.v1.models.User;
import rw.auth.v1.payload.ApiResponse;
import rw.auth.v1.services.IFileService;
import rw.auth.v1.services.IRoleService;
import rw.auth.v1.services.IUserService;
import rw.auth.v1.utils.Constants;
import rw.auth.v1.utils.Formatter;
import rw.auth.v1.utils.Mapper;

import javax.validation.Valid;
import java.util.Collections;
import java.util.UUID;

@RestController
@RequestMapping(path = "/api/v1/users")
public class UserController {

    private final IUserService userService;
    private final IRoleService roleService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final FileStorageService fileStorageService;
    private final IFileService fileService;

    @Value("${uploads.directory.user_profiles}")
    private String directory;

    @Autowired
    public UserController(IUserService userService, IRoleService iRoleService, BCryptPasswordEncoder bCryptPasswordEncoder, FileStorageService fileStorageService, IFileService fileService) {
        this.userService = userService;
        this.roleService = iRoleService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.fileService = fileService;
        this.fileStorageService = fileStorageService;
    }

    @GetMapping(path = "/current-user")
    public ResponseEntity<ApiResponse> currentlyLoggedInUser() {
        return ResponseEntity.ok(new ApiResponse(true, userService.getLoggedInUser()));
    }

    public ResponseEntity<ApiResponse> search(
            @RequestParam(value = "page", defaultValue = Constants.DEFAULT_PAGE_NUMBER) int page,
            @RequestParam(value = "limit", defaultValue = Constants.DEFAULT_PAGE_SIZE) int limit,
            @RequestParam(value = "name", required = false, defaultValue = "") String name,
            @RequestParam(value = "status") EUserStatus status,
            @RequestParam(value = "gender", required = false) EGender gender,
            @RequestParam(value = "role", required = false) ERole role
    ){
        Pageable pageable = PageRequest.of(page,limit, Sort.Direction.ASC,"id");
        if(role != null){
            Role savedRole = roleService.findByName(role);
            return ResponseEntity.ok(ApiResponse.success(userService.search(savedRole,status,name,gender,pageable)));
        }
        return ResponseEntity.ok(ApiResponse.success(userService.search(status,name,gender,pageable)));
    }

    @PostMapping(path = "/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody SignUpDTO dto) {
        if(dto.getRole() == ERole.ADMIN){
            throw new BadRequestException("You can not register yourself as an Admin");
        }

        User user = new User();

        String encodedPassword = bCryptPasswordEncoder.encode(dto.getPassword());
        Role role = roleService.findByName(dto.getRole());

        user.setEmail(dto.getEmail());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setGender(dto.getGender());
        user.setPhoneNumber(dto.getMobile());
        user.setPassword(encodedPassword);
        user.setStatus(EUserStatus.WAIT_EMAIL_VERIFICATION);
        user.setRoles(Collections.singleton(role));

        User entity = this.userService.create(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(new ApiResponse(true, entity));
    }

    @PutMapping(path = "/{id}/upload-profile")
    public ResponseEntity<ApiResponse> uploadProfileImage(
            @PathVariable(value = "id") UUID id,
            @RequestParam("file") MultipartFile document
    ) {
        this.userService.findById(id);
        File file = this.fileService.create(document, directory);

        User updated = this.userService.changeProfileImage(id, file);

        return ResponseEntity.ok(new ApiResponse(true, "File saved successfully", updated));

    }

    @PutMapping("/change-password")
    public ResponseEntity<ApiResponse> changePassword(ChangePasswordDTO dto){
        userService.changePassword(dto);

        return Formatter.done();
    }

    @GetMapping("/files/load-file/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> loadProfileImage(@PathVariable String filename) {

        Resource file = this.fileStorageService.load(directory, filename);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getFilename() + "\"")
                .body(file);
    }

    @PutMapping("/{id/approve")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    public ResponseEntity<ApiResponse> approveAUser(@PathVariable UUID id){
        User user = userService.findById(id);
        userService.approve(user);
        return ResponseEntity.ok(ApiResponse.success("User approved successfully"));
    }

    @PutMapping("/{id}/reject")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    public ResponseEntity<ApiResponse> rejectAUser(@PathVariable UUID id,@Valid @RequestBody RejectUserDto dto){
        User user = userService.findById(id);
        userService.reject(user,dto.getRejectionMessage());
        return ResponseEntity.ok(ApiResponse.success("User rejected successfully"));
    }

    public ResponseEntity<ApiResponse> deactivateAccount(@PathVariable UUID id){
        User user = userService.findById(id);
        userService.deActivate(user);

        return ResponseEntity.ok(ApiResponse.success("Deactivated successfully"));
    }
}