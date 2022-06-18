package rw.auth.v1.dtos;

import lombok.Data;
import rw.auth.v1.enums.EGender;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;


@Data
public class UpdateUserDTO {
    @NotBlank
    private String firstName;

    @Email
    private String email;

    @NotBlank
    private String lastName;

    @Pattern(regexp = "[0-9]{9,10}", message = "Your phone is not a valid tel we expect 07***")
    private  String mobile;

    @NotNull
    private EGender gender;
}
