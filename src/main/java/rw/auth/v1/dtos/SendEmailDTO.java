package rw.auth.v1.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
public class SendEmailDTO {

    @NotBlank
    private  String subject;

    @NotBlank
    private  String nameOfRecipient;

    @NotBlank
    private  String emailOfRecipient;

    @NotBlank
    private  String content;
}
