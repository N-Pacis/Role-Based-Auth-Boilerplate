package rw.auth.v1.serviceImpls;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import rw.auth.v1.dtos.ChangePasswordDTO;
import rw.auth.v1.enums.EUserStatus;
import rw.auth.v1.exceptions.BadRequestException;
import rw.auth.v1.exceptions.ResourceNotFoundException;
import rw.auth.v1.fileHandling.File;
import rw.auth.v1.models.Role;
import rw.auth.v1.models.User;
import rw.auth.v1.repositories.IUserRepository;
import rw.auth.v1.services.IRoleService;
import rw.auth.v1.services.IUserService;
import rw.auth.v1.services.MailService;
import rw.auth.v1.utils.Mapper;
import rw.auth.v1.utils.Profile;

import java.util.*;

@Service
public class UserServiceImpl implements IUserService {

    private final MailService mailService;
    private final IRoleService roleService;
    private final IUserRepository userRepository;

    @Autowired
    public UserServiceImpl(IRoleService iRoleService, MailService mailService, IUserRepository userRepository) {
        this.mailService = mailService;
        this.roleService = iRoleService;
        this.userRepository = userRepository;
    }

    @Override
    public User findById(UUID id) {
        return this.userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException("User", "id", id.toString()));
    }

    @Override
    public User create(User user) {
        validateNewRegistration(user);

        mailService.sendAccountVerificationEmail(user);

        return this.userRepository.save(user);
    }

    @Override
    public User save(User user) {

        return userRepository.save(user);
    }

    @Override
    public User update(UUID id, User user) {
        User entity = this.userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException("User", "id", id.toString()));

        Optional<User> userOptional = this.userRepository.findByEmailOrPhoneNumber(user.getEmail(), user.getPhoneNumber());
        if (userOptional.isPresent() && (userOptional.get().getId() != entity.getId()))
            throw new BadRequestException(String.format("User with email '%s' or phone number '%s' already exists", user.getEmail(), user.getPhoneNumber()));

        entity.setEmail(user.getEmail());
        entity.setFirstName(user.getFirstName());
        entity.setLastName(user.getLastName());
        entity.setPhoneNumber(user.getPhoneNumber());
        entity.setGender(user.getGender());

        return this.userRepository.save(entity);
    }

    @Override
    public boolean isNotUnique(User user) {
        Optional<User> userOptional = this.userRepository.findByEmailOrPhoneNumber(user.getEmail(), user.getPhoneNumber());
        return userOptional.isPresent();
    }

    @Override
    public boolean isNotUniqueInVerified(User user) {
        try {
            Optional<User> userOptional = this.userRepository.findByEmailOrPhoneNumberAndStatusNot(user.getEmail(), user.getPhoneNumber(), EUserStatus.WAIT_EMAIL_VERIFICATION);
            return userOptional.isPresent();
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public void validateNewRegistration(User user) {
        if (isNotUniqueInVerified(user)) {
            throw new BadRequestException(String.format("User with email '%s' or phone number '%s' already exists", user.getEmail(), user.getPhoneNumber()));
        } else if (isNotUnique(user)) {
                throw new BadRequestException(String.format("User with email '%s' or phone number '%s'", user.getEmail(), user.getPhoneNumber()));
        }
    }

    @Override
    public User getLoggedInUser() {
        if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() == "anonymousUser")
            throw new BadRequestException("You are not logged in, try to log in");

        String email;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            email = ((UserDetails) principal).getUsername();
        } else {
            email = principal.toString();
        }

        return userRepository.findByEmail(email).orElseThrow(
                () -> new ResourceNotFoundException("User", "id", email));
    }

    @Override
    public Profile getLoggedInProfile() {
        User theUser = getLoggedInUser();
        Object profile;
        Optional<Role> role = theUser.getRoles().stream().findFirst();
        if (role.isPresent()) {
            switch (role.get().getName()) {
                case STANDARD:
                    profile = theUser;
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + role.get().getName());
            }

            return new Profile(profile);
        }

        return null;
    }

    @Override
    public User getByEmail(String email) {
        return this.userRepository.findByEmail(email).orElseThrow(
                () -> new ResourceNotFoundException("User", "email", email));
    }

    @Override
    public void verifyEmail(String email, String activationCode) {
        User user = getByEmail(email);

        if (!Objects.equals(user.getActivationCode(), activationCode))
            throw new BadRequestException("Invalid Activation Code ..");

        verifyEmail(user);
    }

    @Override
    public void verifyEmail(User user) {

        if (user.getStatus() != EUserStatus.WAIT_EMAIL_VERIFICATION)
            throw new BadRequestException("Your account is " + user.getStatus().toString().toLowerCase(Locale.ROOT));

        user.setStatus(EUserStatus.ACTIVE);

        userRepository.save(user);

        mailService.sendEmailVerifiedMail(user);
        mailService.sendWelcomeEmailMail(user);
        List<User> usersToNotify = new ArrayList<>();
    }

    @Override
    public User changeProfileImage(UUID id, File file) {
        User entity = this.userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException("Document", "id", id.toString()));

        entity.setProfileImage(file);
        return this.userRepository.save(entity);

    }

    @Override
    public boolean isCodeValid(String email, String activationCode) {
        return userRepository.existsByActivationCodeAndEmail(activationCode, email);
    }

    @Override
    public void changePassword(ChangePasswordDTO dto) {
        User user = getLoggedInUser();

        if (Mapper.compare(user.getPassword(), dto.getCurrentPassword()))
            throw new BadRequestException("Invalid current password");

        user.setPassword(Mapper.encode(dto.getNewPassword()));

        userRepository.save(user);
    }
}
