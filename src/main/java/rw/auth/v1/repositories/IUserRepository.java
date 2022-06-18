package rw.auth.v1.repositories;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import rw.auth.v1.enums.EGender;
import rw.auth.v1.enums.EUserStatus;
import rw.auth.v1.models.Role;
import rw.auth.v1.models.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IUserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);


    boolean existsByActivationCodeAndEmail(String activationCode, String email);


    Optional<User> findByEmailOrPhoneNumber(String email, String phoneNumber);


    @Query("SELECT u FROM User u WHERE  ( (u.email = :email ) OR (u.phoneNumber = :phoneNumber ))  AND (u.status <> :status) ")
    Optional<User> findByEmailOrPhoneNumberAndStatusNot(String email, String phoneNumber, EUserStatus status);

}
