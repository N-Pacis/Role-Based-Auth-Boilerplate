package rw.auth.v1.services;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import rw.auth.v1.dtos.ChangePasswordDTO;
import rw.auth.v1.enums.EGender;
import rw.auth.v1.enums.ERole;
import rw.auth.v1.enums.EUserStatus;
import rw.auth.v1.fileHandling.File;
import rw.auth.v1.models.Role;
import rw.auth.v1.models.User;
import rw.auth.v1.utils.Profile;

import java.util.List;
import java.util.UUID;


public interface IUserService {

    User findById(UUID id);

    User create(User user);

    User save(User user);

    User update(UUID id, User user);

    boolean isNotUnique(User user);

    boolean isNotUniqueInVerified(User user);

    void validateNewRegistration(User user);

    User getLoggedInUser();

    Profile getLoggedInProfile();

    User getByEmail(String email);

    void verifyEmail(String email, String activationCode);

    void verifyEmail(User user);

    User changeProfileImage(UUID id, File file);

    boolean isCodeValid(String email, String activationCode);

    void changePassword(ChangePasswordDTO dto);
}