package rw.auth.v1.dtos;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import java.util.UUID;

@Data
public class VerifyUserEmailDTO {

    @Email
    String email;

    @NotEmpty
    String activationCode;
}
