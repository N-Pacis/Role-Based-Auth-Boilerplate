package rw.auth.v1.dtos;

import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Getter
public class CheckActivationCodeDto {

    @NotBlank
    @Email
    String email;

    @NotBlank
    String activationCode;
}
