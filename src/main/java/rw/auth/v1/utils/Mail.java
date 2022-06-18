package rw.auth.v1.utils;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Mail {

    private String appName;

    private String subject;

    private String fullNames;

    private String toEmail;

    private String template;

    private Object data;

    private Object otherData;

    public Mail(String appName, String subject, String fullNames, String toEmail, String template, Object data) {
        this.appName = appName;
        this.subject = subject;
        this.fullNames = fullNames;
        this.toEmail = toEmail;
        this.template = template;
        this.data = data;
    }
}
